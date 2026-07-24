// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Content non-inheritance — the metal's half of "a reborn tenant inherits nothing" (M5 Arc 5)
//!
//! `hv-core` proves a reborn slot inherits no **authority**: no grant, no port, no owned frame
//! (design-lesson #15's inbound-reference sweep, live on the metal since M5 Arc 0). It says nothing
//! about **content**, and it never can — `Mfn` is an opaque token by design, the same fence that
//! abstracts the guest-physical→machine map and 512-slot tables (design-lesson #14e). So content
//! non-inheritance is an obligation the fence assigns **downward**, and this module is where the
//! metal discharges it.
//!
//! ## The statement audit: the ledger named ONE of three channels
//!
//! The deferral ledger said *"frame-content scrubbing on reuse."* Enumerating everything a guest can
//! write that outlives a `DomainDestroy` found three reachable channels, not one (#37):
//!
//! | channel | reachable by the next tenant | closed by |
//! |---|---|---|
//! | model data frames | yes — the machine frame is a pure function of the `Mfn` | [`stage2::scrub_frame`] at allocate |
//! | CoW disk overlay | yes — `discard_overlay` existed but was wired to **no** teardown path | [`on_destroy`] |
//! | virtio device state | partly — `status`/`queue_ready`/`interrupt_status` read straight back; stale queue addresses survive but fail closed behind `backend_authorize`'s grant check | [`on_destroy`] |
//!
//! Two further surfaces are named and **not** closed here, deliberately: the guest code image (RO+X
//! in Stage-2, so no guest can write it — not a channel at all), and the bump-allocated heap, which
//! never reclaims and therefore holds every destroyed domain's model state until reboot. The heap is
//! **not guest-reachable** (it is mapped into no Stage-2), so it is secrets-at-rest inside the
//! trusted layer, not a cross-tenant channel. Recorded rather than discovered later.
//!
//! ## The seam — allocate versus free, and why the first choice was the wrong one
//!
//! A frame must pass through `Frame::Free` between owners (`p2m::allocate` requires it), so the
//! transition pair *allocate* / *free* are **equally complete** hooks: neither can be skipped on a
//! path from one tenant to the next. M5 Arc 5 picked **allocate**. Arc 6b-pre moved it to **free**,
//! and the move is not a wash — free is better on every axis that came up:
//!
//! - **Nothing is left at rest.** Scrubbing at allocate leaves a dead tenant's bytes sitting in DRAM
//!   from the free until the next allocate. Scrubbing at free closes that window — this was Arc 5's
//!   own residual #1, now discharged rather than carried.
//! - **It does not erase pre-loaded content.** A real guest's payload (kernel, DTB, initramfs) is
//!   deposited into guest RAM *before* the hypervisor runs; scrubbing at allocate would zero it the
//!   moment the model config was built. A never-freed frame is never scrubbed, so free is the only
//!   hook compatible with hosting a real guest at all.
//! - **It costs nothing at boot.** Nothing is freed during setup, so building a large model config
//!   is free; scrubbing at allocate would have zeroed the whole guest RAM window up front.
//!
//! **The seam is transition-agnostic.** Rather than matching on `P2mFree` and `DomainDestroy`, the
//! funnel diffs the model's allocation state against its own shadow after every dispatch and scrubs
//! whatever went allocated → free. So bulk `free_all`, explicit frees, and any freeing transition a
//! later arc adds are covered without a new arm — the seam cannot be forgotten for a new call.
//!
//! ### The intuitive design, and why its soundness turns on a detail nobody would state
//!
//! *"Scrub when a frame's owner changes"* looks equivalent, and whether it works depends entirely on
//! **when you sample the owner**. Both variants were built and booted; they disagree. `hv-core`
//! deliberately has no generation counter (an unbounded incarnation would break the enumerator's
//! finite-state BFS, #15b), so **domain IDs are reused** and a reborn tenant holds the slot under
//! the *same* `DomId`.
//!
//! - Sampled **at reachability time** — the natural, cheap place, since Stage-2 emission already
//!   walks every frame — it is **defeated**: it compares `Some(1)` with `Some(1)` across a
//!   destroy/rebirth, never sees the `None` the free passed through, and scrubs nothing.
//!   *Measured:* the dead tenant's secret came back verbatim.
//! - Sampled **after every transition** it works, because it catches that intermediate `None`.
//!   *Measured:* no leak.
//!
//! So the honest statement is not "owner-diff is wrong" but **"an owner-diff is only sound at a
//! sampling rate that already costs more than the alternative"** — and note that the allocated/free
//! diff this module now uses *is* that sampling rate, arrived at from the other direction: it needs
//! one bit per frame rather than an owner, and it asks the question the property actually cares
//! about (did this frame stop being owned?) rather than a proxy for it.
//!
//! ## Why a funnel is not enough, and what checks it
//!
//! Routing every dispatch through [`dispatch`] puts the obligation in one place — but "every site
//! remembered to use the funnel" is a prose claim across N sites, which is the exact shape M5 Arc 4
//! spent an arc removing. So the scrub is **checked by a second, independent derivation** (#36):
//! [`stage2::build_stage2_from_p2m`] — a different code path, reached at the moment a frame becomes
//! *reachable* rather than *owned* — re-derives allocation state from the model and asserts it
//! agrees with the funnel's shadow ([`shadow_says_allocated`]), halting loudly otherwise. A dispatch
//! that bypasses the funnel does not silently leak; it stops the machine at the next emission.

use core::fmt::Write;

use hv_core::hypervisor::DomId;
use hv_core::p2m::Mfn;
use hv_core::{HvCall, HvError, HvOutcome, Hypervisor};

use crate::cell::BootCell;
use crate::stage2;

/// The metal's shadow of which frames the model reports allocated, refreshed after **every**
/// dispatch through the funnel.
///
/// Two jobs. It is how a **free** is detected (a frame that was allocated and now is not), which is
/// the transition the scrub hangs off; and it is the **independent check** on the funnel itself —
/// the emitter re-derives allocation straight from the model at Stage-2 time and asserts agreement,
/// so a bypassed dispatch is caught rather than silently leaking (#36).
static ALLOCATED: BootCell<[bool; crate::NUM_FRAMES]> =
    BootCell::new("ALLOCATED", [false; crate::NUM_FRAMES]);

/// Which CoW disk tenant a domain's storage lives in, so [`on_destroy`] knows whose overlay to
/// discard. `None` for a domain with no disk bound (most phases). Set by [`bind_tenant`].
static TENANT_OF: BootCell<[Option<usize>; crate::NUM_DOMAINS]> =
    BootCell::new("TENANT_OF", [None; crate::NUM_DOMAINS]);

/// Bind `dom`'s storage to CoW disk tenant `tenant`, so destroying `dom` discards that overlay.
pub(crate) fn bind_tenant(dom: DomId, tenant: usize) {
    let mut map = TENANT_OF.borrow_mut();
    if let Some(slot) = map.get_mut(dom as usize) {
        *slot = Some(tenant);
    }
}

/// The funnel's shadow of whether frame `mfn` is allocated — for the emitter's agreement check.
///
/// The *checker* side, deliberately read from a different place than the scrub is written (#36):
/// Stage-2 emission re-derives allocation straight from the model and compares against this. Equal
/// ⇒ every free reached the funnel and was scrubbed. Unequal ⇒ a dispatch bypassed the funnel, and
/// a frame may be carrying a dead tenant's bytes into a live mapping.
pub(crate) fn shadow_says_allocated(mfn: Mfn) -> bool {
    ALLOCATED
        .borrow_mut()
        .get(mfn as usize)
        .copied()
        .unwrap_or(false)
}

/// **The metal's sole dispatch funnel.** Drive the proven `Hypervisor::dispatch`, then discharge the
/// content obligations the model cannot express.
///
/// Every `hv-metal` dispatch goes through here so the obligations live in one place; the
/// independent Stage-2-time check (see the module docs) is what makes that a *checked* property
/// rather than a discipline everyone has to remember.
pub(crate) fn dispatch(
    hv: &mut Hypervisor,
    caller: DomId,
    call: HvCall,
) -> Result<HvOutcome, HvError> {
    let outcome = hv.dispatch(caller, call);

    // A refused call mutates nothing (design-lesson #9), so it can create no content obligation.
    if outcome.is_ok() {
        if let HvCall::DomainDestroy { target, .. } = call {
            on_destroy(target);
        }
        // **Scrub every frame that just became FREE.** Computed as a diff against the shadow rather
        // than per-transition, so `P2mFree`, `DomainDestroy`'s bulk `free_all`, and any freeing
        // transition a later arc adds all need no arm here — the seam cannot be forgotten for a new
        // call. Cheap: `NUM_FRAMES` reads per dispatch.
        let mut shadow = ALLOCATED.borrow_mut();
        for (mfn, was) in shadow.iter_mut().enumerate() {
            let now = hv.p2m().is_allocated(mfn as Mfn);
            if *was && !now {
                stage2::scrub_frame(mfn as Mfn);
            }
            *was = now;
        }
    }

    outcome
}

/// The non-frame content a destroyed domain leaves behind: its CoW overlay and the device register
/// state it negotiated. Both survive teardown by construction (backend storage is deliberately not
/// part of the model), and neither was wired to any teardown path before this arc.
fn on_destroy(target: DomId) {
    let tenant = TENANT_OF
        .borrow_mut()
        .get(target as usize)
        .copied()
        .flatten();
    if let Some(tenant) = tenant {
        crate::guest::discard_tenant_overlay(tenant);
        let mut uart = crate::uart();
        let _ = writeln!(
            uart,
            "baleen: teardown: domain {target}'s CoW overlay (tenant {tenant}) discarded"
        );
    }
    crate::guest::reset_device_state();
}
