/** Delete every key in a KV namespace whose name has the supplied prefix. */
export async function clearKvPrefix(store: KVNamespace, prefix: string): Promise<void> {
	const list = await store.list({ prefix });
	await Promise.all(list.keys.map((key) => store.delete(key.name)));
}
