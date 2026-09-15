import { describe, it, expect } from 'vitest';
import {
	createRobotsGroupCache,
	getRobotsGroupCacheStats,
	withRobotsGate,
	ROBOTS_CACHE_MAX_BYTES,
	ROBOTS_MAX_BODY_BYTES,
} from '@blackveil/dns-checks';

/**
 * In-flight robots.txt cache reservations (SQ-26). A pending entry used to reserve a
 * worst-case ~2 MiB body, so two concurrent hosts could not both stay cached under the
 * 4 MiB cap and the second gated request per host re-fetched robots.txt. Pending entries
 * now weigh only their key; the retained policy is charged when it settles.
 */
describe('robots group cache: in-flight reservations', () => {
	function deferredRobots(body: string) {
		const releases: Array<() => void> = [];
		const fetches = new Map<string, number>();
		const inner = async (url: string): Promise<Response> => {
			const parsed = new URL(url);
			if (parsed.pathname !== '/robots.txt') return new Response('ok');
			fetches.set(parsed.hostname, (fetches.get(parsed.hostname) ?? 0) + 1);
			await new Promise<void>((resolve) => releases.push(resolve));
			return new Response(body);
		};
		return { inner, releases, fetches };
	}

	it('keeps concurrent in-flight hosts cached so a second request per host reuses the decision', async () => {
		const { inner, releases, fetches } = deferredRobots('User-agent: *\nDisallow: /private\n');
		const cache = createRobotsGroupCache();
		const gated = withRobotsGate(inner, { groupCache: cache });
		const hosts = ['a.example.com', 'b.example.com', 'c.example.com'];

		const first = hosts.map((h) => gated(`https://${h}/`));
		// Second request per host while every robots.txt fetch is still in flight.
		const second = hosts.map((h) => gated(`http://${h}/`));
		await expect.poll(() => releases.length).toBe(3);
		expect(getRobotsGroupCacheStats(cache).entries).toBe(3);
		for (const release of releases) release();
		await Promise.all([...first, ...second]);

		expect(fetches).toEqual(new Map(hosts.map((h) => [h, 1])));
		const stats = getRobotsGroupCacheStats(cache);
		expect(stats.entries).toBe(3);
		expect(stats.retainedBytes).toBeLessThanOrEqual(ROBOTS_CACHE_MAX_BYTES);
	});

	it('still bounds retained bytes when concurrent max-sized policies settle', async () => {
		const prefix = 'User-agent: *\nDisallow: /';
		const maxBody = prefix + 'x'.repeat(ROBOTS_MAX_BODY_BYTES - prefix.length);
		const { inner, releases } = deferredRobots(maxBody);
		const cache = createRobotsGroupCache();
		const gated = withRobotsGate(inner, { groupCache: cache });
		const hosts = ['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com'];

		const requests = hosts.map((h) => gated(`https://${h}/`).catch((err: unknown) => err));
		await expect.poll(() => releases.length).toBe(hosts.length);
		for (const release of releases) {
			release();
			await Promise.resolve();
		}
		await Promise.all(requests);
		// Let every settlement's resize run.
		await new Promise((resolve) => setTimeout(resolve, 0));

		const stats = getRobotsGroupCacheStats(cache);
		// Each settled max-sized policy is charged ~2 MiB; four cannot all be retained.
		expect(stats.retainedBytes).toBeLessThanOrEqual(ROBOTS_CACHE_MAX_BYTES);
		expect(stats.retainedBytes).toBeGreaterThan(ROBOTS_MAX_BODY_BYTES);
		expect(stats.entries).toBeLessThan(hosts.length);
	});
});
