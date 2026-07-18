// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # A bump allocator — so the proven brain can allocate on the metal (Arc 3)
//!
//! Arc 3 links [`hv_core`] and constructs a real `Hypervisor`. The core is `no_std` but not
//! allocation-free: its event-channel port table (and the per-domain `Vec`s a `Hypervisor` holds)
//! need a heap. `hv-core`'s own docs name the contract — *"both implementations supply a global
//! allocator (`hv-sim` via `std`; `hv-metal` will provide one on the metal)"* — so standing up a
//! `#[global_allocator]` is Arc 3's job, not scope creep.
//!
//! ## Contract
//!
//! - **Property:** every `alloc` returns either a pointer to `layout.size()` bytes, correctly
//!   aligned to `layout.align()`, that lies inside [`ARENA`] and overlaps no live allocation, or
//!   null (out of arena). Bytes are zeroed once at boot (the arena lives in `.bss`, which `_start`
//!   zeros) and never handed out twice.
//! - **Check:** constructing a `Hypervisor` (which allocates) and dispatching a hypercall whose
//!   result is a value-checked witness, under QEMU, on every CI boot — a green boot is evidence the
//!   allocation path works on the metal.
//! - **Scope:** *plumbing*. A bump allocator **never reclaims** — [`dealloc`](BumpAlloc::dealloc)
//!   is a no-op — so freed memory is lost until the whole arena resets at the next boot. That is
//!   sufficient and honest for a construct-once, dispatch, and park bring-up (nothing here frees and
//!   re-allocates in a loop). A real reclaiming allocator is a later arc's concern, tied to the
//!   long-running control domain (M5), not this spike. There is no isolation content here.
//!
//! ## Why not `static mut`
//!
//! The arena is a `static` [`UnsafeCell`], not a `static mut`: the cross-arc foundation review of
//! Arcs 0–2 called out the *absence* of any `static mut` as what keeps the metal free of a
//! cross-arc aliasing hazard. Interior mutation through `UnsafeCell` is the sound way to keep a
//! mutable-at-runtime static without a `&mut` to a `static mut` ever existing. The bump offset is a
//! plain [`AtomicUsize`]; today only the boot CPU allocates (secondaries stay PSCI-parked — see
//! `_start`), so the compare-exchange never actually contends, but keeping it atomic makes the
//! allocator sound rather than merely lucky if an AP is ever brought online.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Size of the boot heap. Generous headroom: a small `Hypervisor` (a handful of domains, ports,
/// grants, vCPUs, and frames — see `rust_main`) allocates only a few KiB. The arena is zero-
/// initialized, so it lands in `.bss` (`NOLOAD`) and costs nothing in the image; it only reserves
/// RAM, of which the `virt` machine has ample.
const HEAP_SIZE: usize = 256 * 1024;

/// The backing store, in `.bss`. 16-byte aligned so the first allocation of any ordinary alignment
/// is satisfiable from offset 0. `UnsafeCell` because we hand out `*mut` into it from a shared
/// reference — the sound alternative to a `static mut` (see the module docs).
#[repr(align(16))]
struct Arena(UnsafeCell<[u8; HEAP_SIZE]>);

// SAFETY: the metal is uniprocessor during bring-up (only the boot CPU runs `rust_main`;
// secondaries stay PSCI-parked in `_start`), and all synchronization of the bump offset goes
// through the `AtomicUsize` in `BumpAlloc`. The `UnsafeCell`'s bytes are only ever reached via the
// atomically-reserved, non-overlapping ranges `alloc` returns, so no two accesses alias.
unsafe impl Sync for Arena {}

static ARENA: Arena = Arena(UnsafeCell::new([0; HEAP_SIZE]));

/// A monotonic bump allocator over [`ARENA`]. Hands out aligned, non-overlapping slices by
/// advancing an offset; never reclaims.
pub struct BumpAlloc {
    /// Next free byte, as an offset into [`ARENA`]. Advances monotonically; never rewinds.
    next: AtomicUsize,
}

impl BumpAlloc {
    const fn new() -> Self {
        BumpAlloc {
            next: AtomicUsize::new(0),
        }
    }
}

// SAFETY: `alloc` returns pointers into `ARENA` that are correctly aligned to `layout.align()`,
// span exactly `layout.size()` bytes, and — because the offset only ever advances past the end of
// each reservation via a successful compare-exchange — never overlap a prior live allocation.
// Ranges past the arena end are refused with null. `dealloc` does nothing (bump: no reclaim), which
// is a legal `GlobalAlloc` implementation.
unsafe impl GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // The arena base as an integer address, once. `UnsafeCell::get` yields `*mut [u8; N]`; the
        // cast to `*mut u8` is the element pointer to the first byte.
        // The arena base as a real pointer; the returned pointer is derived from it (via `.add`),
        // never minted from an integer, so it keeps `ARENA`'s provenance.
        let base_ptr = ARENA.0.get() as *mut u8;
        let base = base_ptr as usize;
        let align = layout.align();
        let size = layout.size();
        loop {
            let cur = self.next.load(Ordering::Relaxed);
            // Align the current free address up to the requested alignment, then work back to an
            // arena offset. `align` is a power of two (a `Layout` invariant), so the mask is exact.
            // Real `.bss` addresses are small, so these adds cannot overflow `usize`; the checked
            // forms make that explicit rather than assumed.
            let unaligned = match base.checked_add(cur) {
                Some(v) => v,
                None => return ptr::null_mut(),
            };
            let aligned = match unaligned.checked_add(align - 1) {
                Some(v) => v & !(align - 1),
                None => return ptr::null_mut(),
            };
            let end = match aligned.checked_add(size) {
                Some(v) => v,
                None => return ptr::null_mut(),
            };
            // Out of arena? Refuse. `end - base` is the offset just past this allocation; `>` (not
            // `>=`) because an allocation ending exactly at `HEAP_SIZE` still fits.
            let new_off = end - base;
            if new_off > HEAP_SIZE {
                return ptr::null_mut();
            }
            // Publish the advance. On success the range `[aligned, end)` is ours exclusively. Only
            // the boot CPU allocates today, so this never spins; the loop keeps it correct if an AP
            // is ever brought online. `Relaxed` on both arms is sufficient — the allocator publishes
            // *no* data through `next` (each caller writes its own bytes into a disjoint range), so
            // the only requirement is that two successful reservations never overlap, which the
            // atomic RMW on a strictly-increasing offset guarantees. Any acquire/release needed to
            // hand an allocation between CPUs belongs to that handoff (an `Arc`, a channel), not
            // here. (If an AP is ever onlined, note separately that the boot CPU's `.bss` zeroing —
            // including this arena and `next` — must be made visible to it by the AP bring-up, the
            // usual PSCI/cache-maintenance obligation; the allocator does not depend on the zeroing,
            // since `alloc` returns uninitialized memory by contract.)
            if self
                .next
                .compare_exchange_weak(cur, new_off, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                // Provenance-preserving: derive from `base_ptr`, do not cast the integer address.
                return base_ptr.add(aligned - base);
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator: memory is reclaimed only by resetting the whole arena (a reboot). See the
        // module-level scope note — sufficient for a construct-once, dispatch, and park bring-up.
    }
}

/// The one global allocator. `hv-core`'s `alloc` calls resolve here on the metal.
#[global_allocator]
static HEAP: BumpAlloc = BumpAlloc::new();
