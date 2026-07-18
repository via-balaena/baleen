// SPDX-License-Identifier: Apache-2.0 OR MIT
// Scratch Tier-B probe: which seam configs SATURATE (finite reachable set, all-depths
// theorem) vs which have an UNBOUNDED reachable set (finite only per depth bound).
// Run: cargo run --release --example saturation_probe

use hv_core::p2m::PtLevel;
use hv_core::{HvCall, Hypervisor};
use hv_sim::enumerate::{enumerate, state_key, Config};

fn base() -> Config {
    Config {
        domains: 2,
        ports: 2,
        grants: 2,
        vcpus: 1,
        pcpus: 1,
        frames: 2,
        levels: vec![PtLevel::L1, PtLevel::L2],
        handles: 6,
        evtchn: false,
        grant: false,
        sched: false,
        p2m: false,
        create: false,
        destroy: false,
        delegate: false,
        depth: 5,
        max_states: 6_000_000,
    }
}

fn probe(name: &str, mk: &dyn Fn(u32) -> Config, depths: &[u32]) {
    println!("\n=== {name} ===");
    let mut last = 0usize;
    for &d in depths {
        let cfg = mk(d);
        let out = enumerate(&cfg);
        let tag = if out.violation.is_some() {
            "VIOLATION!"
        } else if out.truncated {
            "truncated (cap)"
        } else if out.saturated {
            "SATURATED (empty frontier — all depths)"
        } else {
            "complete-to-depth (frontier non-empty — MORE states deeper)"
        };
        let delta = out.states as i64 - last as i64;
        println!(
            "  depth {d:2}: {:>10} states  (+{delta:>9})  {tag}",
            out.states
        );
        last = out.states;
        if out.saturated || out.truncated || out.violation.is_some() {
            break;
        }
    }
}

fn main() {
    // ── Bounded configs: expected to SATURATE (find the depth). ──
    probe(
        "affinity (sched+create+destroy, 2 vcpu 2 pcpu)",
        &|d| Config {
            sched: true,
            create: true,
            destroy: true,
            vcpus: 2,
            pcpus: 2,
            depth: d,
            ..base()
        },
        &[14, 16, 18, 20, 22, 24],
    );
    probe(
        "evtchn+sched seam (2 vcpu) — both subsystems bounded",
        &|d| Config {
            evtchn: true,
            sched: true,
            create: true,
            destroy: true,
            vcpus: 2,
            depth: d,
            ..base()
        },
        &[8, 10, 12, 14, 16, 18, 20],
    );
    probe(
        "evtchn only (+create+destroy) — port states bounded",
        &|d| Config {
            evtchn: true,
            create: true,
            destroy: true,
            depth: d,
            ..base()
        },
        &[6, 8, 10, 12, 14, 16],
    );

    // ── Grant WITHOUT p2m: a map can never back onto an owned frame, so `maps` stays 0
    //    and the config is bounded → it SATURATES. ──
    probe(
        "grant only (+create+destroy), NO p2m — bounded (maps can't succeed)",
        &|d| Config {
            grant: true,
            create: true,
            destroy: true,
            depth: d,
            ..base()
        },
        &[3, 4, 5, 6, 7, 8, 9, 10],
    );

    // ── Grant + p2m TOGETHER: now a frame can be allocated, granted, and mapped
    //    repeatedly — `maps`/`refs` grow with each map, so the reachable set is UNBOUNDED
    //    and the count should keep climbing depth over depth (never saturating). ──
    probe(
        "grant + p2m (+create+destroy) — UNBOUNDED: keeps climbing",
        &|d| Config {
            grant: true,
            p2m: true,
            create: true,
            destroy: true,
            depth: d,
            max_states: 3_000_000,
            ..base()
        },
        &[3, 4, 5, 6, 7, 8],
    );

    // ── Direct proof that a grant's `maps` refcount is unbounded once a frame is owned:
    //    allocate frame 0, grant it, then map it N times — each remap a fresh state_key. ──
    println!("\n=== direct: grant `maps` is unbounded once the frame is owned ===");
    let mut hv = Hypervisor::new(2, 2, 8, 1, 1, 2);
    hv.dispatch(
        0,
        HvCall::DomainCreate {
            target: 1,
            may_create: false,
        },
    )
    .unwrap();
    hv.dispatch(0, HvCall::P2mAllocate { mfn: 0 }).unwrap(); // dom0 now OWNS frame 0
    hv.dispatch(
        0,
        HvCall::GrantAccess {
            gref: 0,
            grantee: 1,
            frame: 0,
            readonly: false,
        },
    )
    .unwrap();
    let mut prev = state_key(&hv);
    for i in 1..=10 {
        let r = hv.dispatch(
            1,
            HvCall::GrantMap {
                grantor: 0,
                gref: 0,
                writable: true,
            },
        );
        let k = state_key(&hv);
        let grew = k != prev;
        println!(
            "  map #{i:2}: dispatch_ok={:?}  distinct_new_state={}",
            r.is_ok(),
            grew
        );
        prev = k;
    }
    println!("  ⇒ each successful map bumps `maps`/`refs` with no cap: reachable set is INFINITE,");
    println!("    so a grant+p2m BFS is only ever complete *up to a depth*, never saturated.");
}
