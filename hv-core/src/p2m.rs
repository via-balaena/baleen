// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Page-type accounting — a pure, whole-system state machine
//!
//! Every machine frame a guest touches carries two independent counts. A *reference
//! count* pins the page's existence — while it is non-zero the frame cannot be freed
//! or reallocated, so nothing that still points at it is ever left dangling. A *type*
//! and its *type count* record what the frame is currently being used *as*: ordinary
//! writable memory, or a page table the CPU walks. These two uses are mutually
//! exclusive, and keeping them so is the whole point of this module.
//!
//! This is Xen's third historical XSA factory, after event channels and grant tables.
//! The bugs are all one shape: a frame is validated as a page table (so the hardware
//! interprets its bytes as PTEs) while a *writable* reference to the same frame is
//! still live — the guest writes an arbitrary PTE and walks straight out of its own
//! address space. The `get_page`/`get_page_type`/`put_page_type` refcount dance is
//! exactly where those `PGT_*` typecount errors lived.
//!
//! So the safety property, enforced by construction, is:
//!
//! > **A frame is never referenced as writable and as a page table at the same time.**
//! > `get_type` refuses a writable reference while any page-table reference is live,
//! > and vice-versa; therefore [`Violation::TypeConfusion`] can never arise.
//!
//! Around that sit reference coherence (every typed reference is also an existence
//! reference, so the typed counts never exceed the total — [`Violation::TypedExceedsRefs`])
//! and owner integrity (an allocated frame's owner is a real domain). A frame can only
//! be freed once *nothing* references it, which is what stops the classic
//! reallocate-while-mapped use-after-free. These are the same whole-system,
//! checked-every-transition discipline as [`crate::evtchn`] and [`crate::grant`].
//!
//! **What lives here vs. what does not.** The core owns the *accounting* — the counts,
//! the type exclusivity, the lifecycle. It does *not* own the actual page tables, the
//! EPT/NPT shadowing, or how a guest physical address resolves to a machine frame:
//! that is the fence again, enforced by the HAL/MMU layer on the metal. The core says
//! "this frame is pinned as a page table, so it must not be writable"; the hardware
//! mapping layer is what makes a write to it fault. Nor does the core own the wire
//! format of the memory hypercalls (Xen's `mmu_update`, `MMUEXT_*`) — that is a
//! *personality* concern for M5.
//!
//! `Writable` and `PageTable` stand in for Xen's larger family of mutually-exclusive
//! `PGT_*` type classes (writable, several page-table levels, segment-descriptor
//! pages). Two conflicting types are enough to express — and check — the exclusivity
//! invariant that every one of those classes shares; the model generalises without new
//! ideas.
//!
//! Provenance: the page reference/type-count discipline and the write-xor-pagetable
//! exclusivity rule derived from the public Xen memory-management ABI semantics
//! (`get_page`, `get_page_type`, the `PGT_*`/`PGC_*` count fields) and general OS
//! knowledge — not `xen/`'s GPL implementation. Wire structs and the guest
//! physical-to-machine map intentionally excluded (M5). See `CLEANROOM.md`.

extern crate alloc;

use alloc::vec::Vec;

/// A domain identifier — an index into the system's domain set.
pub type DomId = u16;
/// A machine frame number — an index into the [`System`]'s frame table.
pub type Mfn = u32;

/// A page type a frame can be referenced as. These two are mutually exclusive: a
/// frame referenced as one can never simultaneously be referenced as the other, which
/// is the whole safety property. They stand in for Xen's wider set of exclusive
/// `PGT_*` classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageType {
    /// Ordinary writable memory — the guest may store to it.
    Writable,
    /// A page table the CPU walks — must be immutable to the guest while live.
    PageTable,
}

/// One machine frame's accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// Owned by nobody — free to be allocated. Carries no counts, so a free frame can
    /// never hold a stale reference by construction.
    Free,
    /// Allocated to a domain, with live reference counts.
    Allocated {
        /// The domain the frame belongs to.
        owner: DomId,
        /// Total live references pinning the frame's existence. While non-zero the
        /// frame cannot be freed.
        refs: u32,
        /// How many references require the frame to be writable.
        writable_refs: u32,
        /// How many references require the frame to be a page table.
        pagetable_refs: u32,
    },
}

impl Frame {
    const FREE: Self = Frame::Free;
}

/// The whole-system page state: a flat table of machine frames plus the domain count,
/// so every count can be cross-checked and every owner validated.
pub struct System {
    frames: Vec<Frame>,
    num_domains: usize,
}

/// Why a page operation was rejected. Rejections leave the system unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2mError {
    /// Machine frame number out of range.
    BadFrame,
    /// Owner domain id out of range.
    BadDomain,
    /// The frame was not in a state the operation accepts (allocate a non-free frame,
    /// reference a free one, or drop a reference or type that is not held).
    WrongState,
    /// A type reference was requested that conflicts with the frame's live type — a
    /// writable reference while it is a page table, or vice-versa. **This single guard
    /// is what makes the type-confusion invariant hold by construction.**
    TypePinned,
    /// `free` attempted while the frame still has live references, or a bare `put` that
    /// would strand a typed reference (drop the existence ref out from under it).
    InUse,
    /// A domain tried to free a frame it does not own.
    NotYours,
    /// A reference count would overflow.
    Overflow,
}

/// A named invariant breach, carrying the frame it was found at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// An allocated frame is owned by a domain that does not exist.
    OwnerGhostDomain { mfn: usize },
    /// A frame is referenced as writable *and* as a page table at once — the exact
    /// type-confusion the whole module exists to prevent.
    TypeConfusion { mfn: usize },
    /// The typed references outnumber the total references — a typed reference that is
    /// not also an existence reference, which should be impossible.
    TypedExceedsRefs { mfn: usize },
}

impl System {
    /// A system of `num_frames` machine frames, all free, over `num_domains` domains.
    pub fn new(num_domains: usize, num_frames: usize) -> Self {
        System {
            frames: (0..num_frames).map(|_| Frame::FREE).collect(),
            num_domains,
        }
    }

    // ─── transitions ─────────────────────────────────────────────────────────

    /// Allocate a free frame to `owner`, giving it the single existence reference the
    /// owner holds by owning it. The frame must be free — an allocated frame is never
    /// re-owned in place (free it first), which is what stops a live reference being
    /// silently transferred to a different domain.
    pub fn allocate(&mut self, owner: DomId, mfn: Mfn) -> Result<(), P2mError> {
        if owner as usize >= self.num_domains {
            return Err(P2mError::BadDomain);
        }
        let frame = self.frame_mut(mfn)?;
        if !matches!(frame, Frame::Free) {
            return Err(P2mError::WrongState);
        }
        *frame = Frame::Allocated {
            owner,
            refs: 1,
            writable_refs: 0,
            pagetable_refs: 0,
        };
        self.check_invariants();
        Ok(())
    }

    /// Take a bare existence reference on an allocated frame (Xen's `get_page`): pins
    /// it against being freed, without asserting any type.
    pub fn get(&mut self, mfn: Mfn) -> Result<(), P2mError> {
        match self.frame_mut(mfn)? {
            Frame::Allocated { refs, .. } => {
                *refs = refs.checked_add(1).ok_or(P2mError::Overflow)?;
            }
            Frame::Free => return Err(P2mError::WrongState),
        }
        self.check_invariants();
        Ok(())
    }

    /// Drop a bare existence reference (Xen's `put_page`). Refuses to drop the last
    /// reference that a live typed reference still depends on — that would leave the
    /// type pinned with nothing keeping the frame alive.
    pub fn put(&mut self, mfn: Mfn) -> Result<(), P2mError> {
        match self.frame_mut(mfn)? {
            Frame::Allocated {
                refs,
                writable_refs,
                pagetable_refs,
                ..
            } => {
                let typed = *writable_refs + *pagetable_refs;
                if *refs == 0 {
                    return Err(P2mError::WrongState);
                }
                // Every typed reference is also an existence reference, so the total
                // may never fall below the typed count. Dropping a bare ref that is
                // actually holding a type up is refused, not silently unsound.
                if *refs - 1 < typed {
                    return Err(P2mError::InUse);
                }
                *refs -= 1;
            }
            Frame::Free => return Err(P2mError::WrongState),
        }
        self.check_invariants();
        Ok(())
    }

    /// Take a typed reference (Xen's `get_page_type`): acquire the frame *as* `ty`,
    /// taking an existence reference at the same time. **Fails with
    /// [`P2mError::TypePinned`] if the frame is already referenced as the other type**
    /// — this is the guard that makes writable-xor-pagetable hold by construction.
    pub fn get_type(&mut self, mfn: Mfn, ty: PageType) -> Result<(), P2mError> {
        match self.frame_mut(mfn)? {
            Frame::Allocated {
                refs,
                writable_refs,
                pagetable_refs,
                ..
            } => {
                // The conflicting type must have no live references at all.
                let conflict = match ty {
                    PageType::Writable => *pagetable_refs,
                    PageType::PageTable => *writable_refs,
                };
                if conflict > 0 {
                    return Err(P2mError::TypePinned);
                }
                // Bump the existence and typed counts together, overflow-checked
                // before either is written so a rejected call mutates nothing.
                let new_refs = refs.checked_add(1).ok_or(P2mError::Overflow)?;
                let slot = match ty {
                    PageType::Writable => &mut *writable_refs,
                    PageType::PageTable => &mut *pagetable_refs,
                };
                let new_typed = slot.checked_add(1).ok_or(P2mError::Overflow)?;
                *slot = new_typed;
                *refs = new_refs;
            }
            Frame::Free => return Err(P2mError::WrongState),
        }
        self.check_invariants();
        Ok(())
    }

    /// Drop a typed reference (Xen's `put_page_type`), releasing both the type claim
    /// and the existence reference it took. Once the last reference of a type is gone
    /// the frame is free to be re-typed as the other. Fails if no such typed reference
    /// is held.
    pub fn put_type(&mut self, mfn: Mfn, ty: PageType) -> Result<(), P2mError> {
        match self.frame_mut(mfn)? {
            Frame::Allocated {
                refs,
                writable_refs,
                pagetable_refs,
                ..
            } => {
                let slot = match ty {
                    PageType::Writable => &mut *writable_refs,
                    PageType::PageTable => &mut *pagetable_refs,
                };
                if *slot == 0 {
                    return Err(P2mError::WrongState);
                }
                *slot -= 1;
                // A typed reference always took an existence reference with it, so refs
                // is guaranteed non-zero here; saturating_sub is belt-and-braces.
                *refs = refs.saturating_sub(1);
            }
            Frame::Free => return Err(P2mError::WrongState),
        }
        self.check_invariants();
        Ok(())
    }

    /// Free a frame back to the pool. **Fails with [`P2mError::InUse`] while any
    /// reference is live** — this guard is what stops a frame being reallocated while
    /// something still points at it. Only the owner may free it.
    pub fn free(&mut self, caller: DomId, mfn: Mfn) -> Result<(), P2mError> {
        match *self.frame(mfn)? {
            Frame::Allocated { owner, refs, .. } => {
                if owner != caller {
                    return Err(P2mError::NotYours);
                }
                if refs > 0 {
                    return Err(P2mError::InUse);
                }
            }
            Frame::Free => return Err(P2mError::WrongState),
        }
        *self.frame_mut(mfn).unwrap() = Frame::FREE;
        self.check_invariants();
        Ok(())
    }

    // ─── queries ──────────────────────────────────────────────────────────────

    /// Whether `mfn` is allocated.
    pub fn is_allocated(&self, mfn: Mfn) -> bool {
        matches!(self.frame(mfn), Ok(Frame::Allocated { .. }))
    }

    /// The owner of an allocated frame, if it is allocated.
    pub fn owner_of(&self, mfn: Mfn) -> Option<DomId> {
        match self.frame(mfn) {
            Ok(Frame::Allocated { owner, .. }) => Some(*owner),
            _ => None,
        }
    }

    /// The total reference count of a frame, if it is allocated.
    pub fn refs(&self, mfn: Mfn) -> Option<u32> {
        match self.frame(mfn) {
            Ok(Frame::Allocated { refs, .. }) => Some(*refs),
            _ => None,
        }
    }

    /// The number of references of `ty` a frame currently holds, if it is allocated.
    pub fn type_refs(&self, mfn: Mfn, ty: PageType) -> Option<u32> {
        match self.frame(mfn) {
            Ok(Frame::Allocated {
                writable_refs,
                pagetable_refs,
                ..
            }) => Some(match ty {
                PageType::Writable => *writable_refs,
                PageType::PageTable => *pagetable_refs,
            }),
            _ => None,
        }
    }

    /// The frame's current type — the one with live references — or `None` if it is
    /// free or allocated but untyped. Well-defined precisely because the two type
    /// counts are never both non-zero.
    pub fn current_type(&self, mfn: Mfn) -> Option<PageType> {
        match self.frame(mfn) {
            Ok(Frame::Allocated {
                writable_refs,
                pagetable_refs,
                ..
            }) => {
                if *writable_refs > 0 {
                    Some(PageType::Writable)
                } else if *pagetable_refs > 0 {
                    Some(PageType::PageTable)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Number of frames in the table.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Number of domains.
    pub fn domain_count(&self) -> usize {
        self.num_domains
    }

    /// How many frames are currently allocated.
    pub fn allocated_count(&self) -> usize {
        self.frames
            .iter()
            .filter(|f| matches!(f, Frame::Allocated { .. }))
            .count()
    }

    // ─── invariants ───────────────────────────────────────────────────────────

    /// The first invariant breach found, or `None` if the system is consistent.
    ///
    /// Checked after every transition by the debug-time assertion, and by release-mode
    /// property tests.
    pub fn first_violation(&self) -> Option<Violation> {
        for (m, frame) in self.frames.iter().enumerate() {
            if let Frame::Allocated {
                owner,
                refs,
                writable_refs,
                pagetable_refs,
            } = *frame
            {
                if owner as usize >= self.num_domains {
                    return Some(Violation::OwnerGhostDomain { mfn: m });
                }
                if writable_refs > 0 && pagetable_refs > 0 {
                    return Some(Violation::TypeConfusion { mfn: m });
                }
                if writable_refs + pagetable_refs > refs {
                    return Some(Violation::TypedExceedsRefs { mfn: m });
                }
            }
        }
        None
    }

    /// Whether every invariant holds (evaluated in release too, for tests).
    pub fn invariants_hold(&self) -> bool {
        self.first_violation().is_none()
    }

    /// Assert the invariants — compiled out in release, hit by every seeded step.
    fn check_invariants(&self) {
        debug_assert!(
            self.first_violation().is_none(),
            "page-type invariant violated: {:?}",
            self.first_violation()
        );
    }

    // ─── internals ────────────────────────────────────────────────────────────

    fn frame(&self, mfn: Mfn) -> Result<&Frame, P2mError> {
        self.frames.get(mfn as usize).ok_or(P2mError::BadFrame)
    }

    fn frame_mut(&mut self, mfn: Mfn) -> Result<&mut Frame, P2mError> {
        self.frames.get_mut(mfn as usize).ok_or(P2mError::BadFrame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys() -> System {
        System::new(3, 8)
    }

    #[test]
    fn allocate_owns_the_frame_with_one_reference() {
        let mut s = sys();
        s.allocate(1, 4).unwrap();
        assert!(s.is_allocated(4));
        assert_eq!(s.owner_of(4), Some(1));
        assert_eq!(s.refs(4), Some(1));
        assert_eq!(s.current_type(4), None);
    }

    #[test]
    fn allocate_into_an_owned_frame_is_refused() {
        let mut s = sys();
        s.allocate(0, 2).unwrap();
        assert_eq!(s.allocate(1, 2), Err(P2mError::WrongState));
    }

    #[test]
    fn writable_and_pagetable_are_mutually_exclusive() {
        let mut s = sys();
        s.allocate(0, 0).unwrap();
        s.get_type(0, PageType::Writable).unwrap();

        // The whole point: cannot take a page-table reference while writable is live.
        assert_eq!(
            s.get_type(0, PageType::PageTable),
            Err(P2mError::TypePinned)
        );
        assert_eq!(s.current_type(0), Some(PageType::Writable));

        // Drop the writable reference; now it may be typed as a page table.
        s.put_type(0, PageType::Writable).unwrap();
        assert_eq!(s.current_type(0), None);
        s.get_type(0, PageType::PageTable).unwrap();
        assert_eq!(s.current_type(0), Some(PageType::PageTable));
        // And now the reverse is refused.
        assert_eq!(s.get_type(0, PageType::Writable), Err(P2mError::TypePinned));
        assert!(s.invariants_hold());
    }

    #[test]
    fn same_type_references_stack_and_unstack() {
        let mut s = sys();
        s.allocate(0, 1).unwrap();
        s.get_type(1, PageType::Writable).unwrap();
        s.get_type(1, PageType::Writable).unwrap();
        assert_eq!(s.type_refs(1, PageType::Writable), Some(2));
        // Each typed reference also took an existence reference: 1 (alloc) + 2.
        assert_eq!(s.refs(1), Some(3));

        s.put_type(1, PageType::Writable).unwrap();
        assert_eq!(s.type_refs(1, PageType::Writable), Some(1));
        assert_eq!(s.current_type(1), Some(PageType::Writable));
        s.put_type(1, PageType::Writable).unwrap();
        assert_eq!(s.current_type(1), None);
        assert_eq!(s.refs(1), Some(1));
        assert!(s.invariants_hold());
    }

    #[test]
    fn free_is_refused_while_referenced_then_allowed() {
        let mut s = sys();
        s.allocate(2, 3).unwrap();
        s.get(3).unwrap(); // refs now 2

        assert_eq!(s.free(2, 3), Err(P2mError::InUse));
        s.put(3).unwrap(); // refs 1 (the allocation reference)
        assert_eq!(s.free(2, 3), Err(P2mError::InUse));
        s.put(3).unwrap(); // refs 0
        assert!(s.free(2, 3).is_ok());
        assert!(!s.is_allocated(3));
        assert!(s.invariants_hold());
    }

    #[test]
    fn only_the_owner_may_free() {
        let mut s = sys();
        s.allocate(1, 5).unwrap();
        s.put(5).unwrap(); // drop the allocation reference so refs == 0
        assert_eq!(s.free(2, 5), Err(P2mError::NotYours));
        assert!(s.free(1, 5).is_ok());
    }

    #[test]
    fn put_cannot_strand_a_typed_reference() {
        let mut s = sys();
        s.allocate(0, 6).unwrap();
        // alloc ref (1) + one writable typed ref (1) → refs 2, writable 1.
        s.get_type(6, PageType::Writable).unwrap();
        assert_eq!(s.refs(6), Some(2));

        // One bare put is fine (drops to refs 1, still >= typed 1)...
        s.put(6).unwrap();
        assert_eq!(s.refs(6), Some(1));
        // ...but the next would drop refs below the live typed count: refused.
        assert_eq!(s.put(6), Err(P2mError::InUse));
        assert_eq!(s.refs(6), Some(1));
        assert!(s.invariants_hold());
    }

    #[test]
    fn typing_a_free_frame_is_refused() {
        let mut s = sys();
        assert_eq!(s.get(0), Err(P2mError::WrongState));
        assert_eq!(s.get_type(0, PageType::Writable), Err(P2mError::WrongState));
        assert_eq!(s.put(0), Err(P2mError::WrongState));
    }

    #[test]
    fn putting_a_type_not_held_is_refused() {
        let mut s = sys();
        s.allocate(0, 0).unwrap();
        assert_eq!(s.put_type(0, PageType::Writable), Err(P2mError::WrongState));
        s.get_type(0, PageType::Writable).unwrap();
        // Held as writable, but no page-table reference to drop.
        assert_eq!(
            s.put_type(0, PageType::PageTable),
            Err(P2mError::WrongState)
        );
    }

    #[test]
    fn bad_ids_are_rejected() {
        let mut s = sys();
        assert_eq!(s.allocate(9, 0), Err(P2mError::BadDomain));
        assert_eq!(s.allocate(0, 99), Err(P2mError::BadFrame));
        assert_eq!(s.get(99), Err(P2mError::BadFrame));
        assert_eq!(s.free(0, 99), Err(P2mError::BadFrame));
    }

    #[test]
    fn a_frame_recycles_cleanly_through_owners() {
        let mut s = sys();
        s.allocate(0, 7).unwrap();
        s.get_type(7, PageType::PageTable).unwrap();
        s.put_type(7, PageType::PageTable).unwrap();
        s.put(7).unwrap(); // drop allocation reference
        s.free(0, 7).unwrap();
        // A fresh owner gets a clean frame — no stale type or count survives free.
        s.allocate(1, 7).unwrap();
        assert_eq!(s.owner_of(7), Some(1));
        assert_eq!(s.refs(7), Some(1));
        assert_eq!(s.current_type(7), None);
        assert!(s.invariants_hold());
    }
}
