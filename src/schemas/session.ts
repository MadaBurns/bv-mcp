// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';

/** Session record stored in KV. */
export const SessionRecordSchema = z.object({
	createdAt: z.number(),
	lastAccessedAt: z.number(),
});
