// SPDX-License-Identifier: BUSL-1.1
/**
 * Shared binding-degradation telemetry types for operator-only service bindings
 * (BV_RECON / BV_TLS_PROBE). Unified here so the recon + tls-probe fail-soft
 * clients import ONE definition and cannot drift.
 */

/**
 * Binding-degradation kinds for a PRESENT-but-failing operator service binding.
 * Deliberately excludes absent-binding (BSL self-host — expected, not alertable)
 * and the benign recon 404. Mirrors the matching members on the analytics
 * `degradation` event (`binding_unavailable` | `binding_5xx` | `binding_timeout`).
 */
export type BindingDegradationKind = 'binding_unavailable' | 'binding_5xx' | 'binding_timeout';

/**
 * Optional telemetry callback invoked ONLY when a present binding fails. The
 * caller forwards a sink that emits the analytics `degradation` event; the
 * binding additionally emits a structured warn log on its own. Fail-soft: the
 * binding never throws if the sink does.
 *
 * `component` carries which binding failed (`recon` | `tls_probe`).
 */
export type BindingDegradationSink = (event: { degradationType: BindingDegradationKind; component: string; domain?: string }) => void;
