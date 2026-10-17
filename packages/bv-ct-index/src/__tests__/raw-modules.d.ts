// SPDX-License-Identifier: BUSL-1.1
// Vite's `?raw` suffix imports a file as a string; the tests use it to apply the D1 migrations.
declare module '*?raw' {
	const text: string;
	export default text;
}
