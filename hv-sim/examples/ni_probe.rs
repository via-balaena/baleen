// SPDX-License-Identifier: Apache-2.0 OR MIT
// Scratch Tier-D probe: the non-interference bridge coverage over the real code. For each
// config it reports the reachable-state count, the total (state, transition, observer)
// checks, how many of those exercised the UNAUTHORIZED case (the anti-vacuity witness), and
// whether any local-respect violation was found under the full authorized-channel relation.
// Run: cargo run --release --example ni_probe

use hv_core::p2m::PtLevel;
use hv_sim::enumerate::Config;
use hv_sim::noninterference::{check, Channels};

/// The two-domain integrated config (every direct channel; the CI test runs it at depth 3).
fn cfg2(depth: u32) -> Config {
    Config {
        domains: 2,
        ports: 2,
        grants: 2,
        vcpus: 1,
        pcpus: 1,
        frames: 2,
        levels: vec![PtLevel::L1, PtLevel::L2],
        handles: 3,
        evtchn: true,
        grant: true,
        sched: true,
        p2m: true,
        create: true,
        destroy: true,
        delegate: false,
        depth,
        max_states: 200_000,
        symmetry: false,
    }
}

/// The three-domain lean config where the intransitive teardown-reach flow is live.
fn cfg3(depth: u32) -> Config {
    Config {
        domains: 3,
        ports: 1,
        grants: 1,
        vcpus: 0,
        pcpus: 0,
        frames: 1,
        levels: vec![],
        handles: 2,
        evtchn: true,
        grant: true,
        sched: false,
        p2m: false,
        create: true,
        destroy: true,
        delegate: false,
        depth,
        max_states: 400_000,
        symmetry: false,
    }
}

fn main() {
    for (name, cfg) in [
        ("2dom d3 (CI)", cfg2(3)),
        ("2dom d6 deep", cfg2(6)),
        ("3dom d6 deep", cfg3(6)),
    ] {
        let o = check(&cfg, Channels::full());
        println!(
            "{name:>13}: states={:>7}  checks={:>9}  unauthorized={:>9}  violation={}",
            o.states,
            o.checks,
            o.unauthorized_checks,
            o.violation.is_some()
        );
    }
}
