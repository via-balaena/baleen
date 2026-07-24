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
//! ## The seam — and the intuitive one that is WRONG
//!
//! The obvious design is *"scrub when a frame's owner changes."* **It fails on exactly the case this
//! arc exists for.** `hv-core` deliberately has no generation counter — an unbounded incarnation
//! would break the enumerator's finite-state BFS, so domain **IDs are reused** and a reborn tenant
//! occupies the slot under the *same* `DomId` (design-lesson #15b). An owner-diff therefore sees
//! `Some(2) → Some(2)` across a destroy/rebirth and scrubs **nothing**. The very choice that makes
//! the model checkable defeats the intuitive seam.
//!
//! What works instead is keying on the transition that **creates** ownership. `p2m::allocate` is the
//! sole place a frame becomes `Frame::Allocated` from `Free` (the only `*frame = Frame::Allocated`
//! assignment in `hv-core/src/p2m.rs`), so **scrub on a successful `P2mAllocate`** is complete by
//! construction, whoever held the frame before and whatever their `DomId` was. It is also correctly
//! *ordered*: a frame becomes guest-reachable only through a Stage-2 leaf, which requires a link,
//! which requires the allocate — so the scrub always precedes reachability.
//!
//! ## Why a funnel is not enough, and what checks it
//!
//! Routing every dispatch through [`dispatch`] puts the obligation in one place — but "every site
//! remembered to use the funnel" is a prose claim across N sites, which is the exact shape M5 Arc 4
//! spent an arc removing. So the scrub is **checked by a second, independent derivation** (#36):
//! [`stage2::build_stage2_from_p2m`] — a different code path, reached at the moment a frame becomes
//! *reachable* rather than *owned* — asserts via [`is_scrubbed`] that every frame it is about to map
//! was scrubbed since it became allocated, and halts loudly otherwise. A dispatch that bypasses the
//! funnel does not silently leak; it stops the machine at the next Stage-2 emission.

use core::fmt::Write;

use hv_core::hypervisor::DomId;
use hv_core::p2m::Mfn;
use hv_core::{HvCall, HvError, HvOutcome, Hypervisor};

use crate::cell::BootCell;
use crate::stage2;

/// Per-frame "scrubbed since it became allocated". Set by the scrub at `P2mAllocate`; cleared for any
/// frame the model reports is no longer allocated (so a free→allocate cycle cannot reuse a stale
/// `true`). Over-clearing is harmless — it can only cause an extra scrub, never a missed one.
static SCRUBBED: BootCell<[bool; crate::NUM_FRAMES]> =
    BootCell::new("SCRUBBED", [false; crate::NUM_FRAMES]);

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

/// Has model frame `mfn` been scrubbed since it became allocated?
///
/// The *checker* side of the obligation, deliberately derived from a different place than the scrub
/// itself (#36): this is read at Stage-2 emission — when a frame becomes **reachable** — while the
/// scrub happens at allocate, when it becomes **owned**.
pub(crate) fn is_scrubbed(mfn: Mfn) -> bool {
    SCRUBBED
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
        match call {
            // The sole owner-creating transition — see the module docs on why this, and not an
            // owner-diff, is the complete seam.
            HvCall::P2mAllocate { mfn } => {
                stage2::scrub_frame(mfn);
                if let Some(slot) = SCRUBBED.borrow_mut().get_mut(mfn as usize) {
                    *slot = true;
                }
            }
            HvCall::DomainDestroy { target, .. } => on_destroy(target),
            _ => {}
        }
        // Re-sync the shadow against the model: any frame that is no longer allocated must lose its
        // `scrubbed` mark, or a later re-allocation could inherit it. Cheap (`NUM_FRAMES` reads) and
        // transition-agnostic, so a future call that frees a frame needs no new arm here.
        let mut scrubbed = SCRUBBED.borrow_mut();
        for (mfn, slot) in scrubbed.iter_mut().enumerate() {
            if !hv.p2m().is_allocated(mfn as Mfn) {
                *slot = false;
            }
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
