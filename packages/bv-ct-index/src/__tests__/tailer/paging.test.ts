// SPDX-License-Identifier: BUSL-1.1
import { beforeEach, describe, expect, it } from 'vitest';
import {
	MAX_STEP_UP_AFTER_PAGES,
	RFC6962_PAGE,
	STEPPED_DOWN_PAGE,
	STEP_UP_AFTER_PAGES,
	isAligned,
	pageServed,
	pageSizeOf,
	resetPaging,
	stepDown,
} from '../../tailer/paging';

const serve = (logId: string, pages: number) => {
	for (let i = 0; i < pages; i++) pageServed(logId);
};

/** Good pages a stepped-down log needs before it asks for the full size again. */
const pagesToStepUp = (logId: string) => {
	let pages = 0;
	while (pageSizeOf(logId) < RFC6962_PAGE) {
		pageServed(logId);
		pages++;
		if (pages > MAX_STEP_UP_AFTER_PAGES * 2) throw new Error('never stepped up');
	}
	return pages;
};

describe('paging', () => {
	beforeEach(() => resetPaging());

	it('a step-down asks for aligned small pages, and enough good pages bring the full size back', () => {
		stepDown('a');
		expect(pageSizeOf('a')).toBe(STEPPED_DOWN_PAGE);
		expect(isAligned('a')).toBe(true);
		expect(pagesToStepUp('a')).toBe(STEP_UP_AFTER_PAGES);
		expect(isAligned('a')).toBe(false);
	});

	it('a relapse right after a step-up doubles the pages required, up to the maximum', () => {
		stepDown('a');
		pagesToStepUp('a');
		stepDown('a');
		expect(pagesToStepUp('a')).toBe(STEP_UP_AFTER_PAGES * 2);
		for (let i = 0; i < 10; i++) {
			stepDown('a');
			pagesToStepUp('a');
		}
		stepDown('a');
		expect(pagesToStepUp('a')).toBe(MAX_STEP_UP_AFTER_PAGES);
	});

	it('a log that holds the full size forgets the doubling, so occasional timeouts do not ratchet it', () => {
		stepDown('a');
		pagesToStepUp('a');
		// Holds the full size for a while, then one more timeout.
		serve('a', STEP_UP_AFTER_PAGES);
		stepDown('a');
		expect(pagesToStepUp('a')).toBe(STEP_UP_AFTER_PAGES);
	});

	it('keeps each log apart', () => {
		stepDown('a');
		expect(pageSizeOf('b')).toBe(RFC6962_PAGE);
		expect(isAligned('b')).toBe(false);
	});
});
