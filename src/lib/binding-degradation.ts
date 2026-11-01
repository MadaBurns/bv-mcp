// SPDX-License-Identifier: BUSL-1.1
/**
 * Shared binding-degradation telemetry types for operator-only service bindings
 * (BV_RECON / BV_TLS_PROBE). Unified here so the recon + tls-probe fail-soft
 * clients import ONE definition and cannot drift.
 */

/**
 * Binding-degradation kinds for a PRESENT-but-failing operator service binding.
 * Deliberately excludes absent-binding (BSL self-host — expected, not alertable).
 * Mirrors the matching members on the analytics `degradation` event
 * (`binding_unavailable` | `binding_5xx` | `binding_timeout` | `binding_route_absent`).
 *
 * `binding_route_absent` is a recon 404 on `/osint/check`: the binding answered but
 * the upstream does not serve that route (SQ-502/SQ-514). The caller still reports
 * the enrichment as unavailable, but it is a known standing condition rather than an
 * outage, so `queryBindingDegradation` excludes it from the paging alert while it
 * stays queryable in Analytics Engine (and is the signal that bv2-recon has started
 * serving the route once it stops appearing).
 */
export type BindingDegradationKind = 'binding_unavailable' | 'binding_5xx' | 'binding_timeout' | 'binding_route_absent';

/**
 * Optional telemetry callback invoked ONLY when a present binding fails. The
 * caller forwards a sink that emits the analytics `degradation` event; the
 * binding additionally emits a structured warn log on its own. Fail-soft: the
 * binding never throws if the sink does.
 *
 * `component` carries which binding failed (`recon` | `tls_probe`).
 */
export type BindingDegradationSink = (event: { degradationType: BindingDegradationKind; component: string; domain?: string }) => void;
