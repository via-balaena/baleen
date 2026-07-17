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
//! **The reference count is a single scalar, so every acquire must be balanced by
//! exactly one release.** That balance is not something a guest can be trusted to
//! keep: [`System::get`]/[`System::put`] and [`System::get_type`]/[`System::put_type`]
//! are *internal* primitives, driven only by higher-level operations that gate the
//! release on proof of the acquire — a grant map is released only by unmapping its
//! handle, a page-table pin only by unpinning. They are deliberately **not** exposed
//! as guest hypercalls (a raw "drop a reference" call would let one domain release a
//! reference another domain holds, freeing or re-typing a page out from under it —
//! exactly the class of bug this module exists to prevent). The guest-facing surface
//! is only allocate and free; references appear and vanish underneath, always in
//! balanced pairs. This is how Xen's own scalar `count_info` stays sound.
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

/// The level of a page table in the paging hierarchy — Xen's `PGT_l1..l4` classes.
/// A four-level tree (as on x86-64): an `L4` table's entries point to `L3` tables,
/// `L3`→`L2`, `L2`→`L1`, and an `L1` table's entries map ordinary [`PageType::Writable`]
/// leaves. The levels are *ordered and strictly decreasing along a link*, which is what
/// makes the page-table graph acyclic by construction (the linking discipline arrives
/// with the hierarchical invariant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PtLevel {
    /// Bottom level — its entries map ordinary pages.
    L1,
    /// Points to `L1` tables.
    L2,
    /// Points to `L2` tables.
    L3,
    /// Top level (the root the CPU's `%cr3` names) — points to `L3` tables.
    L4,
}

impl PtLevel {
    /// The type a *present entry* of a table at this level must reference: an `L(k-1)`
    /// page table for `k >= 2`, and an ordinary writable leaf for `L1`. This single rule
    /// is the whole paging hierarchy — the linking discipline (and its invariant) will
    /// enforce it holds for every live edge.
    pub fn child_type(self) -> PageType {
        match self {
            PtLevel::L1 => PageType::Writable,
            PtLevel::L2 => PageType::PageTable(PtLevel::L1),
            PtLevel::L3 => PageType::PageTable(PtLevel::L2),
            PtLevel::L4 => PageType::PageTable(PtLevel::L3),
        }
    }
}

/// A page type a frame can be referenced as. All of these are mutually exclusive: a
/// frame referenced as one can never simultaneously be referenced as another, which is
/// the whole safety property. `PageTable` carries the paging [`PtLevel`], so the family
/// is `Writable` plus one type per level — Xen's mutually-exclusive `PGT_*` classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageType {
    /// Ordinary writable memory — the guest may store to it.
    Writable,
    /// A page table the CPU walks at level [`PtLevel`] — must be immutable to the guest
    /// while live, and (once linked) may only reference frames of the level below it.
    PageTable(PtLevel),
}

impl PageType {
    /// The paging level this type is a page table at, or `None` if it is `Writable`.
    pub fn level(self) -> Option<PtLevel> {
        match self {
            PageType::Writable => None,
            PageType::PageTable(level) => Some(level),
        }
    }
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
        /// Outstanding references pinning the frame's existence, *beyond* ownership
        /// itself (grant maps, later page-table pins). While non-zero the frame cannot
        /// be freed — so ownership alone (`refs == 0`) is freeable, but a page anything
        /// else still holds is not.
        refs: u32,
        /// How many references require the frame to be writable.
        writable_refs: u32,
        /// How many references require the frame to be a page table *at `pt_level`*.
        pagetable_refs: u32,
        /// Which paging level this frame is a page table at. Meaningful only while
        /// `pagetable_refs > 0` (as `dispatched_at` is meaningful only while a vCPU
        /// runs); a frame with no page-table references carries no level, and the next
        /// page-table reference sets it afresh. A single field, so a frame can never be
        /// two levels at once — level-exclusivity is enforced by construction.
        pt_level: PtLevel,
        /// Whether the owner has *pinned* this frame as a page table — a persistent
        /// page-table type reference held until explicitly unpinned (Xen's
        /// `PGT_pinned`). One of possibly several page-table references, so `pinned`
        /// implies `pagetable_refs >= 1` but not the reverse.
        pinned: bool,
    },
}

impl Frame {
    const FREE: Self = Frame::Free;
}

/// How many entry slots a page-table frame has. A real x86-64 table holds 512; the
/// model only needs enough to build a branching tree and exercise the hierarchy, so it
/// stays small and the `links` table stays bounded.
pub const TABLE_SLOTS: u32 = 8;

/// One live page-table *entry* — a directed edge from a `parent` table's `slot` to the
/// `child` frame it references. Held in one global table (like the grant module's live
/// mappings) so the hierarchy can be cross-checked against the frame types after every
/// transition. Slots are reused once inactive, so the table stays bounded by peak
/// concurrent links.
#[derive(Debug, Clone, Copy, Default)]
struct Link {
    active: bool,
    parent: Mfn,
    slot: u32,
    child: Mfn,
}

/// The whole-system page state: a flat table of machine frames plus every domain's
/// page-table links, so every count can be cross-checked, every owner validated, and
/// every page-table edge checked level-correct.
pub struct System {
    frames: Vec<Frame>,
    /// Live page-table entries across all frames — the tree structure whose
    /// level-correctness is the hierarchical invariant.
    links: Vec<Link>,
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
    /// A page-table entry slot is out of range for a table.
    BadSlot,
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
    /// A frame is pinned as a page table but holds no page-table reference — the pin
    /// bit and the page-table count have fallen out of step.
    PinnedNotPageTyped { mfn: usize },
    /// A live page-table entry is *mislevelled*: its parent is not a page table, or its
    /// child is not typed as the level directly below the parent (an `L(k-1)` table, or
    /// a writable leaf under an `L1`). The hierarchical type-confusion the multi-level
    /// invariant exists to prevent — a table whose entries the CPU would walk into a
    /// frame of the wrong kind.
    MislevelledLink { parent: usize, slot: usize },
}

impl System {
    /// A system of `num_frames` machine frames, all free, over `num_domains` domains.
    pub fn new(num_domains: usize, num_frames: usize) -> Self {
        System {
            frames: (0..num_frames).map(|_| Frame::FREE).collect(),
            links: Vec::new(),
            num_domains,
        }
    }

    // ─── transitions ─────────────────────────────────────────────────────────

    /// Allocate a free frame to `owner`. Ownership is the `Allocated` *state* itself,
    /// not a counted reference — so a freshly allocated frame starts with `refs == 0`
    /// and every reference thereafter belongs to something *else* pinning the page (a
    /// grant map, later a page-table pin). The frame must be free — an allocated frame
    /// is never re-owned in place (free it first), which is what stops a live reference
    /// being silently transferred to a different domain.
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
            refs: 0,
            writable_refs: 0,
            pagetable_refs: 0,
            // No page-table reference yet, so the level is a placeholder the first
            // `get_type(PageTable(..))` overwrites; `L1` is as good as any.
            pt_level: PtLevel::L1,
            pinned: false,
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
    /// [`P2mError::TypePinned`] if the frame is already referenced as any *other* type**
    /// — the conflicting writable type, or a page table at a *different level*. This one
    /// guard makes both writable-xor-pagetable and level-exclusivity hold by
    /// construction: a frame is only ever referenced as one type, at one level.
    pub fn get_type(&mut self, mfn: Mfn, ty: PageType) -> Result<(), P2mError> {
        match self.frame_mut(mfn)? {
            Frame::Allocated {
                refs,
                writable_refs,
                pagetable_refs,
                pt_level,
                ..
            } => {
                // Any incompatible live type blocks the acquire. For a writable request
                // that is any page-table reference; for a page-table request it is any
                // writable reference *or* a page table already live at another level.
                let conflict = match ty {
                    PageType::Writable => *pagetable_refs > 0,
                    PageType::PageTable(level) => {
                        *writable_refs > 0 || (*pagetable_refs > 0 && *pt_level != level)
                    }
                };
                if conflict {
                    return Err(P2mError::TypePinned);
                }
                // Bump the existence and typed counts together, overflow-checked before
                // either is written so a rejected call mutates nothing. A page-table
                // reference taken from zero also stamps the frame's level.
                let new_refs = refs.checked_add(1).ok_or(P2mError::Overflow)?;
                let slot = match ty {
                    PageType::Writable => &mut *writable_refs,
                    PageType::PageTable(level) => {
                        if *pagetable_refs == 0 {
                            *pt_level = level;
                        }
                        &mut *pagetable_refs
                    }
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
                pt_level,
                ..
            } => {
                let slot = match ty {
                    PageType::Writable => &mut *writable_refs,
                    // A page-table release must name the level the frame is actually
                    // held at — releasing an `L2` reference from an `L3` frame is a
                    // caller error, not a silent decrement of the wrong count.
                    PageType::PageTable(level) => {
                        if *pagetable_refs == 0 || *pt_level != level {
                            return Err(P2mError::WrongState);
                        }
                        &mut *pagetable_refs
                    }
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

    /// Pin a frame as a page table at `level` (Xen's `MMUEXT_PIN_TABLE`): validate it as
    /// an `L`k table and take a persistent page-table type reference, held until
    /// [`Self::unpin`]. Only the owner may pin its own page tables. **Fails with
    /// [`P2mError::TypePinned`] if the frame is currently referenced as writable, or as a
    /// page table at a *different* level** — the exclusivity guard doing its job at pin
    /// time: a page being written must never become a page table, and a table has exactly
    /// one level. Pinning is how a *root* table (one the CPU's `%cr3` names, with no
    /// parent linking it) holds its own type; interior tables instead take their type from
    /// a parent that links them. The two are not exclusive — a pinned table may also be
    /// linked-to — a pin is just one more page-table reference held until [`Self::unpin`].
    pub fn pin(&mut self, caller: DomId, mfn: Mfn, level: PtLevel) -> Result<(), P2mError> {
        // Validate ownership and that it is not already pinned against an immutable
        // view, so a rejected pin mutates nothing.
        match self.frame(mfn)? {
            Frame::Allocated { owner, pinned, .. } => {
                if *owner != caller {
                    return Err(P2mError::NotYours);
                }
                if *pinned {
                    return Err(P2mError::WrongState);
                }
            }
            Frame::Free => return Err(P2mError::WrongState),
        }
        // Take the page-table type reference at `level` — this enforces the exclusivity
        // (fails `TypePinned` if writable, or a page table at another level) and takes an
        // existence reference. Set the pin bit only once it succeeds. Order matters:
        // `get_type` re-establishes the invariant with the bit still clear, which
        // satisfies `pinned ⇒ pagetable_refs >= 1` vacuously; setting the bit after keeps
        // every intermediate state consistent.
        self.get_type(mfn, PageType::PageTable(level))?;
        if let Frame::Allocated { pinned, .. } = self.frame_mut(mfn).unwrap() {
            *pinned = true;
        }
        self.check_invariants();
        Ok(())
    }

    /// Unpin a frame (Xen's `MMUEXT_UNPIN_TABLE`): drop the persistent page-table type
    /// reference [`Self::pin`] took. Only the owner may unpin, and only a pinned frame
    /// can be unpinned — so exactly one unpin matches each pin.
    pub fn unpin(&mut self, caller: DomId, mfn: Mfn) -> Result<(), P2mError> {
        match self.frame(mfn)? {
            Frame::Allocated { owner, pinned, .. } => {
                if *owner != caller {
                    return Err(P2mError::NotYours);
                }
                if !*pinned {
                    return Err(P2mError::WrongState);
                }
            }
            Frame::Free => return Err(P2mError::WrongState),
        }
        // Release the pin at whatever level the frame is held — a pinned frame always
        // holds a page-table reference, so its `pt_level` is live and current.
        let level = match self.frame(mfn).unwrap() {
            Frame::Allocated { pt_level, .. } => *pt_level,
            Frame::Free => unreachable!("a pinned frame is allocated"),
        };
        // Clear the pin bit *before* releasing the reference, so no intermediate state
        // ever shows a pinned frame with no page-table reference. `put_type` cannot fail
        // here — a pinned frame always holds its page-table reference.
        if let Frame::Allocated { pinned, .. } = self.frame_mut(mfn).unwrap() {
            *pinned = false;
        }
        self.put_type(mfn, PageType::PageTable(level))?;
        self.check_invariants();
        Ok(())
    }

    /// Free a frame back to the pool. **Fails with [`P2mError::InUse`] while any
    /// reference is live** — this guard is what stops a frame being reallocated while
    /// something still points at it (a pinned frame holds its page-table reference, so
    /// it must be unpinned first). Only the owner may free it.
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

    // ─── page-table entries (the hierarchy) ────────────────────────────────────

    /// Install a page-table entry: link `parent`'s `slot` to `child`. `parent` must be a
    /// table the caller owns, at some level `L`k; the entry then references `child` at
    /// **exactly the level below** — an `L(k-1)` table for `k >= 2`, or a writable leaf
    /// under an `L1`. This is the whole paging hierarchy, and it is enforced by the type
    /// system: the link takes a `get_type` reference on `child` at that required type, so
    /// a `child` of the wrong kind (a writable page where a table belongs, a table at the
    /// wrong level, an `L1`'s leaf that is really a page table) is refused with
    /// [`P2mError::TypePinned`] before any edge is recorded.
    ///
    /// The link also takes a page-table reference on `parent` *itself*, so a table stays
    /// typed as long as it has any live entry — it cannot be freed, unpinned to untyped,
    /// or re-typed out from under its children (the reference on `child` likewise stops
    /// the child being freed or re-typed while the parent points at it). Because a link's
    /// child sits one level *below* its parent, the page-table graph is a DAG of depth at
    /// most four — no cycle is representable.
    ///
    /// The caller must own the *table* it is editing, but **`child` may belong to another
    /// domain** — a cross-domain (foreign) entry, the mechanism behind shared page tables
    /// and foreign memory mappings. `p2m` enforces only the type discipline here; whether
    /// the caller is *authorized* to reference a foreign frame is a cross-subsystem
    /// question (it must hold a grant from the frame's owner), checked at the dispatch
    /// seam — the same split as the grant↔page-type join.
    pub fn link(
        &mut self,
        caller: DomId,
        parent: Mfn,
        slot: u32,
        child: Mfn,
    ) -> Result<(), P2mError> {
        if slot >= TABLE_SLOTS {
            return Err(P2mError::BadSlot);
        }
        // The caller must own the table it is editing. Validate everything against an
        // immutable view first, so a rejected link mutates nothing.
        let level = match self.frame(parent)? {
            Frame::Allocated {
                owner, pt_level, ..
            } => {
                if *owner != caller {
                    return Err(P2mError::NotYours);
                }
                // `parent` must actually be a page table now — read its level.
                if self.current_type(parent) != Some(PageType::PageTable(*pt_level)) {
                    return Err(P2mError::WrongState);
                }
                *pt_level
            }
            Frame::Free => return Err(P2mError::WrongState),
        };
        // `child` need only be allocated — it may belong to another domain (a foreign
        // entry). Its *owner* keeps it whatever type the reference below demands, so no
        // ownership check here; authorization is the seam's.
        if !self.is_allocated(child) {
            return Err(P2mError::WrongState);
        }
        // The slot must be empty — an entry is never overwritten in place (unlink it
        // first), which keeps a live edge from being silently re-pointed.
        if self.link_index(parent, slot).is_some() {
            return Err(P2mError::WrongState);
        }

        // Take the child reference at the required level — this is the guard that makes
        // the hierarchy hold: it fails unless `child` is (or can become) exactly the
        // level below `parent`. Then take the parent self-reference, which cannot fail
        // (`parent` is already that level). If the second acquire somehow overflowed,
        // roll the first back so a rejected link mutates nothing.
        let child_type = level.child_type();
        self.get_type(child, child_type)?;
        if let Err(e) = self.get_type(parent, PageType::PageTable(level)) {
            let _ = self.put_type(child, child_type);
            return Err(e);
        }
        self.alloc_link(Link {
            active: true,
            parent,
            slot,
            child,
        });
        self.check_invariants();
        Ok(())
    }

    /// Remove the page-table entry at `parent`'s `slot`, dropping the two references the
    /// [`Self::link`] took — the child's level reference and the parent's self-reference.
    /// Only the owner may edit its tables. Once a table's last entry is unlinked (and it
    /// is unpinned, with no parent still pointing at it) it becomes untyped and freeable.
    pub fn unlink(&mut self, caller: DomId, parent: Mfn, slot: u32) -> Result<(), P2mError> {
        let level = match self.frame(parent)? {
            Frame::Allocated {
                owner, pt_level, ..
            } => {
                if *owner != caller {
                    return Err(P2mError::NotYours);
                }
                *pt_level
            }
            Frame::Free => return Err(P2mError::WrongState),
        };
        let idx = self.link_index(parent, slot).ok_or(P2mError::WrongState)?;
        let child = self.links[idx].child;
        // Deactivate the edge first, then release both references. Neither release can
        // fail: the link took and held them, so they are exactly the ones it gives back.
        self.links[idx].active = false;
        let rc = self.put_type(parent, PageType::PageTable(level));
        debug_assert!(
            rc.is_ok(),
            "unlink could not release its parent ref: {rc:?}"
        );
        let cc = self.put_type(child, level.child_type());
        debug_assert!(cc.is_ok(), "unlink could not release its child ref: {cc:?}");
        self.check_invariants();
        Ok(())
    }

    // ─── teardown ─────────────────────────────────────────────────────────────

    /// Remove every page-table entry `owner`'s tables hold — the page-table-structure
    /// step of tearing a domain down, so its tables lose the self-references their
    /// entries pin and can then be unpinned and freed. Order-independent: a table keeps
    /// its page-table type as long as it has any live entry (each entry pins it), so
    /// every [`Self::unlink`] here finds its parent still a valid table and succeeds by
    /// construction. Links are intra-domain (a link's parent and child share an owner),
    /// so this touches nothing another domain holds.
    pub fn unlink_all(&mut self, owner: DomId) {
        for idx in 0..self.links.len() {
            let link = self.links[idx];
            if link.active && self.owner_of(link.parent) == Some(owner) {
                let r = self.unlink(owner, link.parent, link.slot);
                debug_assert!(r.is_ok(), "unlink_all hit a non-removable entry: {r:?}");
            }
        }
    }

    /// Unpin every page-table frame `owner` owns — the first page step of tearing a
    /// domain down, so its page tables can then be freed. Each such frame is pinned and
    /// owned by `owner`, so every [`Self::unpin`] succeeds by construction.
    pub fn unpin_all(&mut self, owner: DomId) {
        for mfn in 0..self.frames.len() as Mfn {
            if self.owner_of(mfn) == Some(owner) && self.is_pinned(mfn) {
                let r = self.unpin(owner, mfn);
                debug_assert!(r.is_ok(), "unpin_all hit a non-unpinnable frame: {r:?}");
            }
        }
    }

    /// Free every frame `owner` owns — the final page step of teardown. By the time
    /// this runs every reference into `owner`'s frames is gone: its own grant maps were
    /// drained, its pins dropped by [`Self::unpin_all`], and the teardown refused up
    /// front if any foreign map remained. So each [`Self::free`] succeeds by
    /// construction.
    pub fn free_all(&mut self, owner: DomId) {
        for mfn in 0..self.frames.len() as Mfn {
            if self.owner_of(mfn) == Some(owner) {
                let r = self.free(owner, mfn);
                debug_assert!(r.is_ok(), "free_all hit a still-referenced frame: {r:?}");
            }
        }
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

    /// The number of references of `ty` a frame currently holds, if it is allocated. A
    /// page-table type at a level the frame is *not* held at reads as zero — the frame
    /// carries references at exactly one level.
    pub fn type_refs(&self, mfn: Mfn, ty: PageType) -> Option<u32> {
        match self.frame(mfn) {
            Ok(Frame::Allocated {
                writable_refs,
                pagetable_refs,
                pt_level,
                ..
            }) => Some(match ty {
                PageType::Writable => *writable_refs,
                PageType::PageTable(level) => {
                    if *pagetable_refs > 0 && *pt_level == level {
                        *pagetable_refs
                    } else {
                        0
                    }
                }
            }),
            _ => None,
        }
    }

    /// The frame's current type — the one with live references, page tables carrying
    /// their level — or `None` if it is free or allocated but untyped. Well-defined
    /// precisely because a frame is never referenced as two types (or two levels) at
    /// once.
    pub fn current_type(&self, mfn: Mfn) -> Option<PageType> {
        match self.frame(mfn) {
            Ok(Frame::Allocated {
                writable_refs,
                pagetable_refs,
                pt_level,
                ..
            }) => {
                if *writable_refs > 0 {
                    Some(PageType::Writable)
                } else if *pagetable_refs > 0 {
                    Some(PageType::PageTable(*pt_level))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Whether a frame is pinned as a page table.
    pub fn is_pinned(&self, mfn: Mfn) -> bool {
        matches!(self.frame(mfn), Ok(Frame::Allocated { pinned: true, .. }))
    }

    /// The frame a table's `slot` currently points at, if there is a live entry there.
    pub fn child_at(&self, parent: Mfn, slot: u32) -> Option<Mfn> {
        self.link_index(parent, slot).map(|i| self.links[i].child)
    }

    /// Total live page-table entries across the whole system.
    pub fn active_links(&self) -> usize {
        self.links.iter().filter(|l| l.active).count()
    }

    /// Every live page-table entry as a `(parent, slot, child)` triple. The integrating
    /// layer uses this to reason about *cross-domain* entries — a link whose `parent` and
    /// `child` have different owners — which `p2m` itself is deliberately blind to
    /// (ownership authorization lives at the seam, not in the type discipline).
    pub fn link_edges(&self) -> Vec<(Mfn, u32, Mfn)> {
        self.links
            .iter()
            .filter(|l| l.active)
            .map(|l| (l.parent, l.slot, l.child))
            .collect()
    }

    /// Whether any live page-table entry points at a frame `owner` owns *from a table
    /// another domain owns* — i.e. a foreign domain has one of `owner`'s frames mapped
    /// into its own page tables. The page-table cousin of
    /// [`crate::grant::System::has_foreign_map`], and part of the domain-teardown
    /// precondition: such a frame cannot be reclaimed out from under the foreign mapper.
    pub fn has_foreign_link_into(&self, owner: DomId) -> bool {
        self.links.iter().any(|l| {
            l.active
                && self.owner_of(l.child) == Some(owner)
                && self.owner_of(l.parent) != Some(owner)
        })
    }

    /// Whether `frame` is referenced by any live page-table entry from a table another
    /// domain owns — a foreign mapping of this specific frame. The seam uses it to refuse
    /// revoking a grant while a foreign page-table entry still relies on it.
    pub fn is_foreign_linked(&self, frame: Mfn) -> bool {
        let owner = self.owner_of(frame);
        self.links
            .iter()
            .any(|l| l.active && l.child == frame && self.owner_of(l.parent) != owner)
    }

    /// Whether `frame` is foreign-mapped *specifically by `linker`* — a live page-table
    /// entry from one of `linker`'s tables onto `frame`, which `linker` does not own. Lets
    /// the seam refuse revoking a grant only when *that grant's grantee* relies on it,
    /// rather than any grant of the frame.
    pub fn is_foreign_linked_by(&self, frame: Mfn, linker: DomId) -> bool {
        let owner = self.owner_of(frame);
        self.links.iter().any(|l| {
            l.active
                && l.child == frame
                && self.owner_of(l.parent) == Some(linker)
                && Some(linker) != owner
        })
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
                pinned,
                pt_level: _,
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
                if pinned && pagetable_refs == 0 {
                    return Some(Violation::PinnedNotPageTyped { mfn: m });
                }
            }
        }
        // The hierarchy: every live entry points from a table to a frame of exactly the
        // level below it. `link` establishes this by construction (it takes the child's
        // type reference at the required level and the parent's at its own), so a breach
        // here means the type bookkeeping and the recorded edges have fallen out of step.
        for link in self.links.iter().filter(|l| l.active) {
            let ok = match self.current_type(link.parent) {
                Some(PageType::PageTable(level)) => {
                    self.current_type(link.child) == Some(level.child_type())
                }
                // Parent is untyped, writable, or free — not a table at all.
                _ => false,
            };
            if !ok {
                return Some(Violation::MislevelledLink {
                    parent: link.parent as usize,
                    slot: link.slot as usize,
                });
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

    /// The index of the live entry at `(parent, slot)`, if any.
    fn link_index(&self, parent: Mfn, slot: u32) -> Option<usize> {
        self.links
            .iter()
            .position(|l| l.active && l.parent == parent && l.slot == slot)
    }

    /// Record a link, reusing an inactive slot if one is free so the table stays bounded
    /// by peak concurrent links.
    fn alloc_link(&mut self, link: Link) {
        if let Some(i) = self.links.iter().position(|l| !l.active) {
            self.links[i] = link;
        } else {
            self.links.push(link);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys() -> System {
        System::new(3, 8)
    }

    #[test]
    fn allocate_owns_the_frame_with_no_outstanding_references() {
        let mut s = sys();
        s.allocate(1, 4).unwrap();
        assert!(s.is_allocated(4));
        assert_eq!(s.owner_of(4), Some(1));
        // Ownership is the state itself, not a counted reference.
        assert_eq!(s.refs(4), Some(0));
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
            s.get_type(0, PageType::PageTable(PtLevel::L1)),
            Err(P2mError::TypePinned)
        );
        assert_eq!(s.current_type(0), Some(PageType::Writable));

        // Drop the writable reference; now it may be typed as a page table.
        s.put_type(0, PageType::Writable).unwrap();
        assert_eq!(s.current_type(0), None);
        s.get_type(0, PageType::PageTable(PtLevel::L1)).unwrap();
        assert_eq!(s.current_type(0), Some(PageType::PageTable(PtLevel::L1)));
        // And now the reverse is refused.
        assert_eq!(s.get_type(0, PageType::Writable), Err(P2mError::TypePinned));
        assert!(s.invariants_hold());
    }

    #[test]
    fn a_frame_is_never_two_page_table_levels_at_once() {
        let mut s = sys();
        s.allocate(0, 0).unwrap();
        // Take an L2 reference; the frame is now an L2 table.
        s.get_type(0, PageType::PageTable(PtLevel::L2)).unwrap();
        assert_eq!(s.current_type(0), Some(PageType::PageTable(PtLevel::L2)));

        // A *different* level is refused just like the writable/page-table conflict —
        // a table has exactly one level.
        assert_eq!(
            s.get_type(0, PageType::PageTable(PtLevel::L3)),
            Err(P2mError::TypePinned)
        );
        assert_eq!(
            s.get_type(0, PageType::PageTable(PtLevel::L1)),
            Err(P2mError::TypePinned)
        );
        // The same level stacks, and reads back only at that level.
        s.get_type(0, PageType::PageTable(PtLevel::L2)).unwrap();
        assert_eq!(s.type_refs(0, PageType::PageTable(PtLevel::L2)), Some(2));
        assert_eq!(s.type_refs(0, PageType::PageTable(PtLevel::L3)), Some(0));

        // Once every L2 reference is gone the frame is free to be typed at a new level.
        s.put_type(0, PageType::PageTable(PtLevel::L2)).unwrap();
        s.put_type(0, PageType::PageTable(PtLevel::L2)).unwrap();
        assert_eq!(s.current_type(0), None);
        s.get_type(0, PageType::PageTable(PtLevel::L3)).unwrap();
        assert_eq!(s.current_type(0), Some(PageType::PageTable(PtLevel::L3)));
        // Releasing at the wrong level is refused, not a silent decrement.
        assert_eq!(
            s.put_type(0, PageType::PageTable(PtLevel::L2)),
            Err(P2mError::WrongState)
        );
        assert!(s.invariants_hold());
    }

    #[test]
    fn same_type_references_stack_and_unstack() {
        let mut s = sys();
        s.allocate(0, 1).unwrap();
        s.get_type(1, PageType::Writable).unwrap();
        s.get_type(1, PageType::Writable).unwrap();
        assert_eq!(s.type_refs(1, PageType::Writable), Some(2));
        // Each typed reference also took an existence reference (ownership adds none).
        assert_eq!(s.refs(1), Some(2));

        s.put_type(1, PageType::Writable).unwrap();
        assert_eq!(s.type_refs(1, PageType::Writable), Some(1));
        assert_eq!(s.current_type(1), Some(PageType::Writable));
        s.put_type(1, PageType::Writable).unwrap();
        assert_eq!(s.current_type(1), None);
        assert_eq!(s.refs(1), Some(0));
        assert!(s.invariants_hold());
    }

    #[test]
    fn free_is_refused_while_referenced_then_allowed() {
        let mut s = sys();
        s.allocate(2, 3).unwrap(); // refs 0 — ownership only
        s.get(3).unwrap(); // an outstanding reference: refs 1

        assert_eq!(s.free(2, 3), Err(P2mError::InUse));
        s.put(3).unwrap(); // refs 0
        assert!(s.free(2, 3).is_ok());
        assert!(!s.is_allocated(3));
        assert!(s.invariants_hold());
    }

    #[test]
    fn only_the_owner_may_free() {
        let mut s = sys();
        s.allocate(1, 5).unwrap(); // refs 0 — freeable by the owner right away
        assert_eq!(s.free(2, 5), Err(P2mError::NotYours));
        assert!(s.free(1, 5).is_ok());
    }

    #[test]
    fn put_cannot_strand_a_typed_reference() {
        let mut s = sys();
        s.allocate(0, 6).unwrap();
        // One bare existence ref plus one writable typed ref → refs 2, writable 1.
        s.get(6).unwrap();
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
            s.put_type(0, PageType::PageTable(PtLevel::L1)),
            Err(P2mError::WrongState)
        );
    }

    #[test]
    fn unpin_all_and_free_all_clear_a_domains_frames() {
        let mut s = sys();
        // Domain 0 owns three frames: one pinned as a page table, one plainly owned,
        // one owned with an untyped existence reference it will drop before teardown.
        s.allocate(0, 0).unwrap();
        s.pin(0, 0, PtLevel::L1).unwrap();
        s.allocate(0, 1).unwrap();
        s.allocate(0, 2).unwrap();
        // A frame owned by a *different* domain must survive domain 0's teardown.
        s.allocate(1, 5).unwrap();

        // Unpin first, so the pinned frame becomes freeable...
        s.unpin_all(0);
        assert!(!s.is_pinned(0));
        assert_eq!(s.refs(0), Some(0));
        // ...then free every frame domain 0 owns.
        s.free_all(0);
        assert!(!s.is_allocated(0));
        assert!(!s.is_allocated(1));
        assert!(!s.is_allocated(2));
        assert_eq!(
            s.owner_of(5),
            Some(1),
            "another domain's frame is untouched"
        );
        assert!(s.invariants_hold());
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
    fn pin_types_the_frame_as_a_page_table() {
        let mut s = sys();
        s.allocate(0, 2).unwrap();
        // Pin it as an L4 table (a root the CPU's %cr3 would name).
        s.pin(0, 2, PtLevel::L4).unwrap();
        assert!(s.is_pinned(2));
        assert_eq!(s.current_type(2), Some(PageType::PageTable(PtLevel::L4)));
        assert_eq!(s.type_refs(2, PageType::PageTable(PtLevel::L4)), Some(1));
        // The pin took an existence reference with the type reference.
        assert_eq!(s.refs(2), Some(1));
        assert!(s.invariants_hold());
    }

    #[test]
    fn pinning_twice_is_refused() {
        let mut s = sys();
        s.allocate(0, 0).unwrap();
        s.pin(0, 0, PtLevel::L1).unwrap();
        assert_eq!(s.pin(0, 0, PtLevel::L1), Err(P2mError::WrongState));
        // Still pinned exactly once.
        assert_eq!(s.type_refs(0, PageType::PageTable(PtLevel::L1)), Some(1));
        assert!(s.invariants_hold());
    }

    #[test]
    fn cannot_pin_a_frame_that_is_referenced_writable() {
        let mut s = sys();
        s.allocate(0, 1).unwrap();
        s.get_type(1, PageType::Writable).unwrap();
        // A page being written must never become a page table.
        assert_eq!(s.pin(0, 1, PtLevel::L1), Err(P2mError::TypePinned));
        assert!(!s.is_pinned(1));
        assert!(s.invariants_hold());
    }

    #[test]
    fn cannot_writable_type_a_pinned_frame() {
        let mut s = sys();
        s.allocate(0, 3).unwrap();
        s.pin(0, 3, PtLevel::L2).unwrap();
        // The reverse: a live page table can't be taken writable.
        assert_eq!(s.get_type(3, PageType::Writable), Err(P2mError::TypePinned));
        assert!(s.invariants_hold());
    }

    #[test]
    fn only_the_owner_may_pin_or_unpin() {
        let mut s = sys();
        s.allocate(1, 4).unwrap();
        assert_eq!(s.pin(2, 4, PtLevel::L1), Err(P2mError::NotYours));
        s.pin(1, 4, PtLevel::L1).unwrap();
        assert_eq!(s.unpin(2, 4), Err(P2mError::NotYours));
        assert!(s.unpin(1, 4).is_ok());
    }

    #[test]
    fn unpin_requires_a_prior_pin() {
        let mut s = sys();
        s.allocate(0, 5).unwrap();
        assert_eq!(s.unpin(0, 5), Err(P2mError::WrongState));
        s.pin(0, 5, PtLevel::L3).unwrap();
        s.unpin(0, 5).unwrap();
        // The pin is spent — unpinning again is refused.
        assert_eq!(s.unpin(0, 5), Err(P2mError::WrongState));
    }

    #[test]
    fn a_pinned_frame_cannot_be_freed_until_unpinned() {
        let mut s = sys();
        s.allocate(0, 6).unwrap();
        s.pin(0, 6, PtLevel::L1).unwrap();
        assert_eq!(s.free(0, 6), Err(P2mError::InUse));
        s.unpin(0, 6).unwrap();
        assert!(s.free(0, 6).is_ok());
        assert!(s.invariants_hold());
    }

    #[test]
    fn pin_unpin_round_trip_leaves_a_clean_frame() {
        let mut s = sys();
        s.allocate(0, 7).unwrap();
        // Unpin must release at the frame's own level — pin L3, unpin, clean.
        s.pin(0, 7, PtLevel::L3).unwrap();
        s.unpin(0, 7).unwrap();
        assert!(!s.is_pinned(7));
        assert_eq!(s.current_type(7), None);
        assert_eq!(s.refs(7), Some(0));
        // With the pin gone the frame is free to be taken writable.
        assert!(s.get_type(7, PageType::Writable).is_ok());
        assert!(s.invariants_hold());
    }

    // Build the canonical L4→L3→L2→L1→leaf chain owned by domain 0 over frames
    // [root, l3, l2, l1, leaf] and return it. Each interior frame is typed purely by
    // being linked; only the root is pinned.
    fn linked_chain(s: &mut System) -> (Mfn, Mfn, Mfn, Mfn, Mfn) {
        let (root, l3, l2, l1, leaf) = (0, 1, 2, 3, 4);
        for m in [root, l3, l2, l1, leaf] {
            s.allocate(0, m).unwrap();
        }
        s.pin(0, root, PtLevel::L4).unwrap();
        s.link(0, root, 0, l3).unwrap(); // L4 -> L3
        s.link(0, l3, 0, l2).unwrap(); //   L3 -> L2
        s.link(0, l2, 0, l1).unwrap(); //   L2 -> L1
        s.link(0, l1, 0, leaf).unwrap(); // L1 -> writable leaf
        (root, l3, l2, l1, leaf)
    }

    #[test]
    fn a_full_four_level_chain_types_every_frame_by_its_level() {
        let mut s = System::new(2, 8);
        let (root, l3, l2, l1, leaf) = linked_chain(&mut s);
        assert_eq!(s.current_type(root), Some(PageType::PageTable(PtLevel::L4)));
        assert_eq!(s.current_type(l3), Some(PageType::PageTable(PtLevel::L3)));
        assert_eq!(s.current_type(l2), Some(PageType::PageTable(PtLevel::L2)));
        assert_eq!(s.current_type(l1), Some(PageType::PageTable(PtLevel::L1)));
        // The leaf under an L1 is ordinary writable memory.
        assert_eq!(s.current_type(leaf), Some(PageType::Writable));
        assert_eq!(s.child_at(root, 0), Some(l3));
        assert_eq!(s.child_at(l1, 0), Some(leaf));
        assert_eq!(s.active_links(), 4);
        assert!(s.invariants_hold());
    }

    #[test]
    fn a_link_refuses_a_child_of_the_wrong_level() {
        let mut s = System::new(2, 8);
        s.allocate(0, 0).unwrap();
        s.allocate(0, 1).unwrap();
        s.allocate(0, 2).unwrap();
        s.pin(0, 0, PtLevel::L4).unwrap(); // an L4 table
        s.pin(0, 2, PtLevel::L2).unwrap(); // and, separately, an L2 table

        // An L4 entry must point at an L3 — pointing at the L2 frame is refused, since
        // the frame is already typed L2 and cannot also be L3.
        assert_eq!(s.link(0, 0, 0, 2), Err(P2mError::TypePinned));
        // Nothing was recorded, and the L2 table is untouched.
        assert_eq!(s.child_at(0, 0), None);
        assert_eq!(s.current_type(2), Some(PageType::PageTable(PtLevel::L2)));
        assert!(s.invariants_hold());

        // Frame 1 is untyped, so linking it as the L4's L3 child *establishes* it as L3.
        s.link(0, 0, 0, 1).unwrap();
        assert_eq!(s.current_type(1), Some(PageType::PageTable(PtLevel::L3)));
        assert!(s.invariants_hold());
    }

    #[test]
    fn a_linked_table_cannot_be_freed_retyped_or_stranded() {
        let mut s = System::new(2, 8);
        let (root, l3, l2, _l1, _leaf) = linked_chain(&mut s);

        // A child cannot be freed while its parent points at it (the reference the link
        // holds keeps it alive) — the cross-level use-after-free the hierarchy prevents.
        assert_eq!(s.free(0, l3), Err(P2mError::InUse));
        // Nor re-typed to another level while linked.
        assert_eq!(
            s.get_type(l3, PageType::PageTable(PtLevel::L2)),
            Err(P2mError::TypePinned)
        );
        // A table with a live entry holds a self-reference, so it too cannot be freed —
        // even after it is unpinned, its children keep it a table.
        s.unpin(0, root).unwrap();
        assert_eq!(s.current_type(root), Some(PageType::PageTable(PtLevel::L4)));
        assert_eq!(s.free(0, root), Err(P2mError::InUse));
        assert!(s.invariants_hold());

        // A table stays typed while it still has *any* child: unlinking L2→L1 alone does
        // not untype the L1, because the L1 keeps a self-reference from its own live
        // entry down to the leaf. The tree must be torn down leaf-upward.
        s.unlink(0, l2, 0).unwrap();
        assert_eq!(
            s.current_type(_l1),
            Some(PageType::PageTable(PtLevel::L1)),
            "the L1 is still a table — it still points at the leaf"
        );
        // Unlink the L1's own entry, and now it is untyped and reclaimable.
        s.unlink(0, _l1, 0).unwrap();
        assert_eq!(s.current_type(_l1), None, "no entries left, so untyped");
        assert_eq!(s.current_type(_leaf), None, "the leaf is ordinary again");
        assert!(s.free(0, _l1).is_ok());
        assert!(s.free(0, _leaf).is_ok());
        assert!(s.invariants_hold());
    }

    #[test]
    fn unlink_all_dismantles_a_domains_whole_tree() {
        let mut s = System::new(2, 8);
        let (root, ..) = linked_chain(&mut s);
        // A frame owned by another domain, linked in its own little table, must survive.
        s.allocate(1, 6).unwrap();
        s.allocate(1, 7).unwrap();
        s.pin(1, 6, PtLevel::L1).unwrap();
        s.link(1, 6, 0, 7).unwrap();

        s.unlink_all(0);
        assert_eq!(s.active_links(), 1, "only domain 1's entry remains");
        // Domain 0's tree is now just types held by pins/links that are gone — unpin the
        // root and every frame it owned is freeable.
        s.unpin(0, root).unwrap();
        for m in 0..5 {
            assert!(s.free(0, m).is_ok(), "frame {m} should be freeable");
        }
        // Domain 1 is untouched.
        assert_eq!(s.child_at(6, 0), Some(7));
        assert!(s.invariants_hold());
    }

    #[test]
    fn link_rejects_bad_slots_non_owner_tables_and_occupied_slots() {
        let mut s = System::new(2, 8);
        s.allocate(0, 0).unwrap();
        s.allocate(0, 1).unwrap();
        s.pin(0, 0, PtLevel::L2).unwrap();

        // Slot out of range.
        assert_eq!(s.link(0, 0, TABLE_SLOTS, 1), Err(P2mError::BadSlot));
        // The caller must own the *table* it edits (though not necessarily the child).
        assert_eq!(s.link(1, 0, 0, 1), Err(P2mError::NotYours));
        // Linking into a frame that is not a table is refused.
        assert_eq!(s.link(0, 1, 0, 0), Err(P2mError::WrongState));

        // A good link, then a second into the same slot is refused (no in-place
        // overwrite); unlinking frees the slot again.
        s.link(0, 0, 0, 1).unwrap();
        assert_eq!(s.link(0, 0, 0, 1), Err(P2mError::WrongState));
        assert_eq!(s.unlink(0, 0, 1), Err(P2mError::WrongState)); // no entry at slot 1
        s.unlink(0, 0, 0).unwrap();
        assert_eq!(s.child_at(0, 0), None);
        assert!(s.invariants_hold());
    }

    #[test]
    fn link_permits_a_foreign_child_at_the_p2m_layer() {
        // `p2m` enforces only the type discipline; a foreign child is allowed here, and
        // *authorization* (a grant) is the dispatch seam's business. Domain 0 links an
        // L1 leaf onto a frame domain 1 owns.
        let mut s = System::new(2, 8);
        s.allocate(0, 0).unwrap();
        s.allocate(1, 2).unwrap(); // a frame domain 1 owns
        s.pin(0, 0, PtLevel::L1).unwrap();

        s.link(0, 0, 0, 2).unwrap();
        assert_eq!(s.child_at(0, 0), Some(2));
        // The foreign frame is now writable-typed and pinned alive by the entry — domain
        // 1 can neither free nor re-type it while domain 0's table points at it.
        assert_eq!(s.current_type(2), Some(PageType::Writable));
        assert_eq!(s.free(1, 2), Err(P2mError::InUse));
        assert!(s.is_foreign_linked(2));
        assert!(s.has_foreign_link_into(1));
        assert!(!s.has_foreign_link_into(0));

        // Unlinking releases it, and now domain 1 can reclaim its frame.
        s.unlink(0, 0, 0).unwrap();
        assert!(!s.is_foreign_linked(2));
        assert_eq!(s.current_type(2), None);
        assert!(s.free(1, 2).is_ok());
        assert!(s.invariants_hold());
    }

    #[test]
    fn a_frame_recycles_cleanly_through_owners() {
        let mut s = sys();
        s.allocate(0, 7).unwrap();
        s.get_type(7, PageType::PageTable(PtLevel::L2)).unwrap();
        s.put_type(7, PageType::PageTable(PtLevel::L2)).unwrap(); // refs back to 0
        s.free(0, 7).unwrap();
        // A fresh owner gets a clean frame — no stale type or count survives free.
        s.allocate(1, 7).unwrap();
        assert_eq!(s.owner_of(7), Some(1));
        assert_eq!(s.refs(7), Some(0));
        assert_eq!(s.current_type(7), None);
        assert!(s.invariants_hold());
    }
}
