// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Grant tables — a pure, whole-system state machine
//!
//! A grant table lets one domain (the *grantor*) permit another (the *grantee*)
//! access to a specific page, by read-only or read-write *grant*. The grantee then
//! *maps* the grant (pinning the page and taking a reference) and later *unmaps* it.
//! This is Xen's other historical XSA factory, and the bugs are all one shape: a
//! grant revoked or repurposed while a mapping is still live → a cross-domain
//! use-after-free.
//!
//! So the safety property, enforced by construction, is:
//!
//! > **A grant with an outstanding map cannot be ended.** `end_access` fails while
//! > the reference count is non-zero; therefore no live mapping ever references a
//! > freed grant.
//!
//! Around that sit refcount consistency (the entry's counts equal the live mappings
//! over it), read-only integrity (a read-only grant is never mapped writable), and
//! grantee identity (only the named domain may map). These are the same
//! whole-system, checked-every-transition discipline as [`crate::evtchn`].
//!
//! **What lives here vs. what does not.** The core owns the grant *lifecycle* and
//! its reference counts. It does *not* own the grant-table wire format (Xen's
//! `grant_entry_v1`/`v2` structs, the status-byte page, versioning) — that is a
//! *personality* concern for `baleen-xenabi` at M5. Pinning a mapped page against
//! reuse is the fence again: the core says "this frame is referenced"; the HAL/EPT
//! layer enforces it on the metal.
//!
//! Provenance: grant lifecycle, the map/unmap reference discipline, and the
//! "no-end-while-mapped" rule derived from the public Xen grant-table ABI semantics
//! and general OS knowledge — not `xen/`'s GPL implementation. Wire structs and
//! versioning intentionally excluded (M5). See `CLEANROOM.md`.

extern crate alloc;

use alloc::vec::Vec;

/// A domain identifier — an index into the [`System`]'s domain table.
pub type DomId = u16;
/// A grant reference — an index into a grantor's grant table.
pub type GrantRef = u32;
/// A machine frame number — which physical page is being granted. Narrowed to the
/// [`crate::p2m::Mfn`] width so a grant and the page-type subsystem name the *same*
/// frame once they are joined at the dispatch seam (a grant map then takes a real p2m
/// reference on this frame). The guest-physical→machine translation that sits above
/// this — a grantor names a GFN in its own address space, which Xen resolves to an MFN
/// on map — is a personality/guest-memory concern deferred to a later milestone; the
/// core models the machine-frame accounting the safety property actually turns on.
pub type Frame = u32;
/// A handle returned by [`System::map`], naming one live mapping.
///
/// A bare slot index, reclaimed by [`System::unmap`] and reused by the next map
/// (there is no generation counter). A stale handle therefore acts on whatever
/// mapping later reused the slot — but [`System::unmap`] requires the caller to be
/// the mapping's grantee, so a domain can only ever confuse *itself* this way, never
/// another domain. Guests must not reuse freed handles, as in Xen.
pub type GrantHandle = u32;

/// What a successful [`System::unmap`] released: the frame the mapping was over and
/// whether it was writable. Returned so an integrating layer (the hypervisor's
/// grant↔page-type seam) can mirror the release into whatever else references the
/// frame — a writable unmap must drop a writable *type* reference, a read-only one only
/// an existence reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unmapped {
    /// The machine frame the released mapping was over.
    pub frame: Frame,
    /// Whether the released mapping was writable.
    pub writable: bool,
}

/// A grant-table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantEntry {
    /// Unused slot.
    Free,
    /// An active permit-access grant.
    Access {
        /// The only domain permitted to map this grant.
        grantee: DomId,
        /// The frame being granted.
        frame: Frame,
        /// Whether write mappings are forbidden.
        readonly: bool,
        /// Number of live mappings over this grant.
        maps: u32,
        /// Number of those mappings that are writable (`<= maps`).
        writable_maps: u32,
    },
}

impl GrantEntry {
    const FREE: Self = GrantEntry::Free;
}

/// One domain's grant table (the grants *it* offers to others).
struct DomainGrants {
    entries: Vec<GrantEntry>,
}

/// One live mapping — the grantee's side of an active grant. Slots are reused once
/// inactive, so the table stays bounded by peak concurrent maps.
#[derive(Debug, Clone, Copy, Default)]
struct Mapping {
    active: bool,
    grantee: DomId,
    grantor: DomId,
    gref: GrantRef,
    writable: bool,
}

/// The whole-system grant state: every domain's grant table plus the global table
/// of live mappings, so refcounts can be cross-checked against reality.
pub struct System {
    domains: Vec<DomainGrants>,
    maps: Vec<Mapping>,
}

/// Why a grant operation was rejected. Rejections leave the system unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    /// Domain id out of range.
    BadDomain,
    /// Grant reference out of range for its grantor.
    BadGrantRef,
    /// Map handle out of range or already unmapped.
    BadHandle,
    /// Entry was not in a state the operation accepts (grant into a non-free slot,
    /// or map/end/copy a slot that is not an active grant).
    WrongState,
    /// `end_access` attempted while the grant still has live mappings.
    InUse,
    /// The mapping domain is not the grant's grantee, or a writable map/copy was
    /// requested against a read-only grant.
    PermissionDenied,
    /// A domain tried to unmap a handle it does not own.
    NotYours,
    /// The reference count would overflow.
    Overflow,
}

/// A named invariant breach, carrying the grant it was found at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// An active grant names a grantee domain that does not exist.
    GranteeGhostDomain { grantor: usize, gref: usize },
    /// An entry's recorded counts disagree with the live mappings over it.
    RefcountMismatch { grantor: usize, gref: usize },
    /// A read-only grant has a writable mapping.
    ReadonlyViolated { grantor: usize, gref: usize },
    /// `writable_maps > maps` — impossible if the counts are consistent.
    WritableExceedsMaps { grantor: usize, gref: usize },
    /// A live mapping references an entry that is not an active, matching grant —
    /// the use-after-free shape the whole module exists to prevent.
    DanglingMap { grantor: usize, gref: usize },
}

impl System {
    /// A system of `num_domains` domains, each offering `entries_per_domain` grant
    /// slots, with no mappings yet.
    pub fn new(num_domains: usize, entries_per_domain: usize) -> Self {
        let make = || DomainGrants {
            entries: (0..entries_per_domain).map(|_| GrantEntry::FREE).collect(),
        };
        System {
            domains: (0..num_domains).map(|_| make()).collect(),
            maps: Vec::new(),
        }
    }

    // ─── transitions ─────────────────────────────────────────────────────────

    /// Grantor offers `frame` to `grantee` at `gref`. The slot must be free — a
    /// grant is never overwritten in place (end it first), which is what keeps a
    /// live mapping from being silently re-pointed at a different page.
    pub fn grant_access(
        &mut self,
        grantor: DomId,
        gref: GrantRef,
        grantee: DomId,
        frame: Frame,
        readonly: bool,
    ) -> Result<(), GrantError> {
        self.domain(grantee)?; // grantee must be a real domain — no ghost
        let entry = self.entry_mut(grantor, gref)?;
        if !matches!(entry, GrantEntry::Free) {
            return Err(GrantError::WrongState);
        }
        *entry = GrantEntry::Access {
            grantee,
            frame,
            readonly,
            maps: 0,
            writable_maps: 0,
        };
        self.check_invariants();
        Ok(())
    }

    /// Grantor revokes a grant. **Fails with [`GrantError::InUse`] while any mapping
    /// is live** — this single guard is what makes the dangling-map invariant hold
    /// by construction.
    pub fn end_access(&mut self, grantor: DomId, gref: GrantRef) -> Result<(), GrantError> {
        match *self.entry(grantor, gref)? {
            GrantEntry::Access { maps, .. } => {
                if maps > 0 {
                    return Err(GrantError::InUse);
                }
            }
            GrantEntry::Free => return Err(GrantError::WrongState),
        }
        *self.entry_mut(grantor, gref).unwrap() = GrantEntry::FREE;
        self.check_invariants();
        Ok(())
    }

    /// Grantee maps a grant, taking a reference and pinning the page. Returns a
    /// handle for the later unmap. Rejects a foreign grantee and a writable map of a
    /// read-only grant.
    pub fn map(
        &mut self,
        grantee: DomId,
        grantor: DomId,
        gref: GrantRef,
        writable: bool,
    ) -> Result<GrantHandle, GrantError> {
        // Validate against an immutable view first; mutate only once it is certain
        // to succeed, so a rejected map is a true no-op.
        let (permitted_grantee, readonly) = match *self.entry(grantor, gref)? {
            GrantEntry::Access {
                grantee, readonly, ..
            } => (grantee, readonly),
            GrantEntry::Free => return Err(GrantError::WrongState),
        };
        if permitted_grantee != grantee {
            return Err(GrantError::PermissionDenied);
        }
        if writable && readonly {
            return Err(GrantError::PermissionDenied);
        }

        // Bump the counts (overflow-checked before any slot is consumed).
        if let GrantEntry::Access {
            maps,
            writable_maps,
            ..
        } = self.entry_mut(grantor, gref).unwrap()
        {
            *maps = maps.checked_add(1).ok_or(GrantError::Overflow)?;
            if writable {
                *writable_maps += 1;
            }
        }
        let handle = self.alloc_handle(Mapping {
            active: true,
            grantee,
            grantor,
            gref,
            writable,
        });
        self.check_invariants();
        Ok(handle)
    }

    /// Grantee unmaps a mapping it owns, releasing its reference. Returns what was
    /// released (frame and writability) so a caller integrating grant tables with the
    /// page-type counts can mirror exactly the reverse of what the map acquired.
    pub fn unmap(&mut self, grantee: DomId, handle: GrantHandle) -> Result<Unmapped, GrantError> {
        let mapping = *self
            .maps
            .get(handle as usize)
            .ok_or(GrantError::BadHandle)?;
        if !mapping.active {
            return Err(GrantError::BadHandle);
        }
        if mapping.grantee != grantee {
            return Err(GrantError::NotYours);
        }
        // The frame comes from the grant entry, which an active mapping always backs
        // onto (the dangling-map invariant), so this pattern always matches.
        let mut frame = 0;
        if let Ok(GrantEntry::Access {
            frame: f,
            maps,
            writable_maps,
            ..
        }) = self.entry_mut(mapping.grantor, mapping.gref)
        {
            frame = *f;
            *maps = maps.saturating_sub(1);
            if mapping.writable {
                *writable_maps = writable_maps.saturating_sub(1);
            }
        }
        self.maps[handle as usize].active = false;
        self.check_invariants();
        Ok(Unmapped {
            frame,
            writable: mapping.writable,
        })
    }

    /// A transient grant-checked access (Xen's `GNTTABOP_copy`): validates the same
    /// permission as [`Self::map`] but takes no reference and changes no state.
    pub fn copy(
        &self,
        grantee: DomId,
        grantor: DomId,
        gref: GrantRef,
        write: bool,
    ) -> Result<(), GrantError> {
        match *self.entry(grantor, gref)? {
            GrantEntry::Access {
                grantee: permitted,
                readonly,
                ..
            } => {
                if permitted != grantee {
                    return Err(GrantError::PermissionDenied);
                }
                if write && readonly {
                    return Err(GrantError::PermissionDenied);
                }
                Ok(())
            }
            GrantEntry::Free => Err(GrantError::WrongState),
        }
    }

    // ─── teardown ─────────────────────────────────────────────────────────────

    /// Unmap *every* live mapping `grantee` holds, returning what each released
    /// ([`Unmapped`]) so the caller can mirror the reverse page reference into the
    /// page-type accounting — the grant side of tearing a domain down. Each unmap is
    /// the ordinary single-mapping transition ([`Self::unmap`]), so the entry counts
    /// stay consistent throughout; `grantee` owns every mapping it holds by
    /// construction, so none can error.
    pub fn drain_maps_of(&mut self, grantee: DomId) -> Vec<Unmapped> {
        let mut released = Vec::new();
        for handle in 0..self.maps.len() as GrantHandle {
            let held = self.maps[handle as usize];
            if held.active && held.grantee == grantee {
                let u = self.unmap(grantee, handle).unwrap();
                released.push(u);
            }
        }
        released
    }

    /// Revoke *every* grant `grantor` offers — the last grant-side step of teardown.
    /// By the time this runs each such grant has no live mappings: the caller has
    /// already drained `grantor`'s own maps (its self-grants included) and refused the
    /// teardown outright if any *foreign* map remained ([`Self::has_foreign_map`]). So
    /// every [`Self::end_access`] here succeeds by construction.
    pub fn revoke_all(&mut self, grantor: DomId) {
        for gref in 0..self.entry_count(grantor) as GrantRef {
            if self.is_granted(grantor, gref) {
                let r = self.end_access(grantor, gref);
                debug_assert!(r.is_ok(), "revoke_all hit a still-mapped grant: {r:?}");
            }
        }
    }

    // ─── queries ──────────────────────────────────────────────────────────────

    /// Whether any grant `target` offers is currently mapped by a *different* domain —
    /// the domain-teardown precondition. A live foreign map holds a page reference that
    /// [`Self::end_access`] and [`crate::p2m::System::free`] would strand, so a domain
    /// with one outstanding cannot be destroyed. A domain's maps of its *own* grants do
    /// not count: teardown unmaps those itself (they are `target`'s to release), so only
    /// a foreign grantee blocks it. A grant map only ever stands over a frame the
    /// grantor owns (the seam refuses a stale grant at map time), so this is exactly
    /// "a foreign domain holds a live map of a frame `target` owns".
    pub fn has_foreign_map(&self, target: DomId) -> bool {
        self.maps
            .iter()
            .any(|m| m.active && m.grantor == target && m.grantee != target)
    }

    /// Whether `grantee` holds any live mapping — used to confirm a torn-down domain
    /// holds none.
    pub fn holds_any_map(&self, grantee: DomId) -> bool {
        self.maps.iter().any(|m| m.active && m.grantee == grantee)
    }

    /// Whether `grantor` currently offers `grantee` an active grant of `frame` — and, if
    /// `writable` is asked, a read-*write* one. This is the *permit* side of the grant
    /// table (distinct from a live map): it answers "may `grantee` access this frame?",
    /// which the dispatch seam uses to authorize a cross-domain page-table entry against
    /// the frame's owner. Returns false if no such grant stands.
    pub fn authorizes(&self, grantor: DomId, grantee: DomId, frame: Frame, writable: bool) -> bool {
        let Ok(dom) = self.domain(grantor) else {
            return false;
        };
        dom.entries.iter().any(|e| {
            matches!(
                e,
                GrantEntry::Access { grantee: g, frame: f, readonly, .. }
                    if *g == grantee && *f == frame && (!writable || !*readonly)
            )
        })
    }

    /// Whether `gref` in `grantor` is an active grant.
    pub fn is_granted(&self, grantor: DomId, gref: GrantRef) -> bool {
        matches!(self.entry(grantor, gref), Ok(GrantEntry::Access { .. }))
    }

    /// The live map count of a grant, if it is active.
    pub fn map_count(&self, grantor: DomId, gref: GrantRef) -> Option<u32> {
        match self.entry(grantor, gref) {
            Ok(GrantEntry::Access { maps, .. }) => Some(*maps),
            _ => None,
        }
    }

    /// The live *writable* map count of a grant, if it is active. Used by the
    /// hypervisor's grant↔page-type cross-check to confirm every writable mapping is
    /// backed by a writable-type reference on the frame.
    pub fn writable_map_count(&self, grantor: DomId, gref: GrantRef) -> Option<u32> {
        match self.entry(grantor, gref) {
            Ok(GrantEntry::Access { writable_maps, .. }) => Some(*writable_maps),
            _ => None,
        }
    }

    /// The domain a grant names as its grantee, if it is active. Lets the seam reason
    /// about *who* a grant authorizes (e.g. whether revoking it would strand a specific
    /// domain's foreign page-table entry), without exposing the entry internals.
    pub fn grantee_of(&self, grantor: DomId, gref: GrantRef) -> Option<DomId> {
        match self.entry(grantor, gref) {
            Ok(GrantEntry::Access { grantee, .. }) => Some(*grantee),
            _ => None,
        }
    }

    /// The frame a grant offers, if it is active.
    pub fn granted_frame(&self, grantor: DomId, gref: GrantRef) -> Option<Frame> {
        match self.entry(grantor, gref) {
            Ok(GrantEntry::Access { frame, .. }) => Some(*frame),
            _ => None,
        }
    }

    /// Total live mappings across the whole system.
    pub fn active_maps(&self) -> usize {
        self.maps.iter().filter(|m| m.active).count()
    }

    /// Number of domains.
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Number of grant slots in a domain (0 if out of range).
    pub fn entry_count(&self, grantor: DomId) -> usize {
        self.domain(grantor).map(|d| d.entries.len()).unwrap_or(0)
    }

    // ─── invariants ───────────────────────────────────────────────────────────

    /// The first invariant breach found, or `None` if the system is consistent.
    pub fn first_violation(&self) -> Option<Violation> {
        // Per-entry: counts agree with reality, read-only holds, grantee exists.
        for (d, dom) in self.domains.iter().enumerate() {
            for (g, entry) in dom.entries.iter().enumerate() {
                if let GrantEntry::Access {
                    grantee,
                    readonly,
                    maps,
                    writable_maps,
                    ..
                } = *entry
                {
                    if grantee as usize >= self.domains.len() {
                        return Some(Violation::GranteeGhostDomain {
                            grantor: d,
                            gref: g,
                        });
                    }
                    if writable_maps > maps {
                        return Some(Violation::WritableExceedsMaps {
                            grantor: d,
                            gref: g,
                        });
                    }
                    if readonly && writable_maps > 0 {
                        return Some(Violation::ReadonlyViolated {
                            grantor: d,
                            gref: g,
                        });
                    }
                    let live = self
                        .maps
                        .iter()
                        .filter(|m| m.active && m.grantor as usize == d && m.gref as usize == g);
                    let total = live.clone().count();
                    let writable = live.filter(|m| m.writable).count();
                    if maps as usize != total || writable_maps as usize != writable {
                        return Some(Violation::RefcountMismatch {
                            grantor: d,
                            gref: g,
                        });
                    }
                }
            }
        }
        // Per-mapping: every live mapping backs onto a matching, active grant.
        for m in self.maps.iter().filter(|m| m.active) {
            let backed = matches!(
                self.entry(m.grantor, m.gref),
                Ok(GrantEntry::Access { grantee, readonly, .. })
                    if *grantee == m.grantee && (!m.writable || !*readonly)
            );
            if !backed {
                return Some(Violation::DanglingMap {
                    grantor: m.grantor as usize,
                    gref: m.gref as usize,
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
            "grant-table invariant violated: {:?}",
            self.first_violation()
        );
    }

    // ─── internals ────────────────────────────────────────────────────────────

    fn alloc_handle(&mut self, mapping: Mapping) -> GrantHandle {
        if let Some(i) = self.maps.iter().position(|m| !m.active) {
            self.maps[i] = mapping;
            i as GrantHandle
        } else {
            self.maps.push(mapping);
            (self.maps.len() - 1) as GrantHandle
        }
    }

    fn domain(&self, dom: DomId) -> Result<&DomainGrants, GrantError> {
        self.domains.get(dom as usize).ok_or(GrantError::BadDomain)
    }

    fn domain_mut(&mut self, dom: DomId) -> Result<&mut DomainGrants, GrantError> {
        self.domains
            .get_mut(dom as usize)
            .ok_or(GrantError::BadDomain)
    }

    fn entry(&self, grantor: DomId, gref: GrantRef) -> Result<&GrantEntry, GrantError> {
        self.domain(grantor)?
            .entries
            .get(gref as usize)
            .ok_or(GrantError::BadGrantRef)
    }

    fn entry_mut(&mut self, grantor: DomId, gref: GrantRef) -> Result<&mut GrantEntry, GrantError> {
        self.domain_mut(grantor)?
            .entries
            .get_mut(gref as usize)
            .ok_or(GrantError::BadGrantRef)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys() -> System {
        System::new(3, 6)
    }

    #[test]
    fn grant_stores_frame_and_marks_active() {
        let mut s = sys();
        s.grant_access(0, 2, 1, 0xF00, false).unwrap();
        assert!(s.is_granted(0, 2));
        assert_eq!(s.granted_frame(0, 2), Some(0xF00));
        assert_eq!(s.map_count(0, 2), Some(0));
    }

    #[test]
    fn end_access_is_refused_while_mapped_then_allowed() {
        let mut s = sys();
        s.grant_access(0, 0, 1, 42, false).unwrap();
        let h = s.map(1, 0, 0, true).unwrap();
        assert_eq!(s.map_count(0, 0), Some(1));

        // The whole point: cannot revoke a grant with a live mapping.
        assert_eq!(s.end_access(0, 0), Err(GrantError::InUse));

        s.unmap(1, h).unwrap();
        assert_eq!(s.map_count(0, 0), Some(0));
        assert!(s.end_access(0, 0).is_ok());
        assert!(s.invariants_hold());
    }

    #[test]
    fn readonly_grant_refuses_writable_map_but_allows_read() {
        let mut s = sys();
        s.grant_access(0, 1, 2, 7, true).unwrap();
        assert_eq!(s.map(2, 0, 1, true), Err(GrantError::PermissionDenied));
        assert!(s.map(2, 0, 1, false).is_ok());
        assert!(s.invariants_hold());
    }

    #[test]
    fn only_the_named_grantee_may_map() {
        let mut s = sys();
        s.grant_access(0, 0, 1, 9, false).unwrap();
        // Domain 2 is not the grantee.
        assert_eq!(s.map(2, 0, 0, false), Err(GrantError::PermissionDenied));
        assert!(s.map(1, 0, 0, false).is_ok());
    }

    #[test]
    fn a_domain_cannot_unmap_a_handle_it_does_not_own() {
        let mut s = sys();
        s.grant_access(0, 0, 1, 9, false).unwrap();
        let h = s.map(1, 0, 0, false).unwrap();
        assert_eq!(s.unmap(2, h), Err(GrantError::NotYours));
        // The real owner still can.
        assert!(s.unmap(1, h).is_ok());
    }

    #[test]
    fn refcount_tracks_multiple_maps() {
        let mut s = sys();
        s.grant_access(0, 3, 1, 1, false).unwrap();
        let h1 = s.map(1, 0, 3, false).unwrap();
        let h2 = s.map(1, 0, 3, true).unwrap();
        assert_eq!(s.map_count(0, 3), Some(2));
        s.unmap(1, h1).unwrap();
        assert_eq!(s.map_count(0, 3), Some(1));
        s.unmap(1, h2).unwrap();
        assert_eq!(s.map_count(0, 3), Some(0));
        assert!(s.invariants_hold());
    }

    #[test]
    fn copy_enforces_readonly_and_grantee() {
        let mut s = sys();
        s.grant_access(0, 0, 1, 5, true).unwrap();
        assert!(s.copy(1, 0, 0, false).is_ok()); // read copy by grantee: ok
        assert_eq!(s.copy(1, 0, 0, true), Err(GrantError::PermissionDenied)); // write: denied
        assert_eq!(s.copy(2, 0, 0, false), Err(GrantError::PermissionDenied)); // wrong grantee
    }

    #[test]
    fn grant_into_occupied_slot_is_refused() {
        let mut s = sys();
        s.grant_access(0, 0, 1, 1, false).unwrap();
        assert_eq!(
            s.grant_access(0, 0, 2, 2, false),
            Err(GrantError::WrongState)
        );
    }

    #[test]
    fn mapping_a_free_or_ended_grant_is_refused() {
        let mut s = sys();
        assert_eq!(s.map(1, 0, 0, false), Err(GrantError::WrongState));
        s.grant_access(0, 0, 1, 1, false).unwrap();
        s.end_access(0, 0).unwrap();
        assert_eq!(s.map(1, 0, 0, false), Err(GrantError::WrongState));
    }

    #[test]
    fn has_foreign_map_sees_foreign_maps_but_not_self_maps() {
        let mut s = sys();
        // Domain 0 grants two frames: one to a foreign domain, one to itself.
        s.grant_access(0, 0, 1, 100, false).unwrap(); // grantee 1 (foreign)
        s.grant_access(0, 1, 0, 200, false).unwrap(); // grantee 0 (self)
        assert!(!s.has_foreign_map(0), "no maps yet");

        // A self-map must NOT count as a foreign hold — teardown unmaps it itself.
        let self_h = s.map(0, 0, 1, false).unwrap();
        assert!(
            !s.has_foreign_map(0),
            "a self-map is not a foreign hold on the domain"
        );

        // A foreign map does count.
        let foreign_h = s.map(1, 0, 0, false).unwrap();
        assert!(s.has_foreign_map(0), "domain 1's map blocks domain 0");
        // ...but only against the domain that *offered* the mapped grant.
        assert!(!s.has_foreign_map(1), "domain 1 offers no mapped grant");

        // Dropping the foreign map clears it; the lingering self-map still doesn't count.
        s.unmap(1, foreign_h).unwrap();
        assert!(!s.has_foreign_map(0));
        s.unmap(0, self_h).unwrap();
        assert!(s.invariants_hold());
    }

    #[test]
    fn authorizes_reports_the_permit_a_grantor_offers() {
        let mut s = sys();
        // Domain 0 grants frame 42 read-write to domain 1, and frame 7 read-only to it.
        s.grant_access(0, 0, 1, 42, false).unwrap();
        s.grant_access(0, 1, 1, 7, true).unwrap();

        // A read-write grant authorizes both a writable and a read-only reference.
        assert!(s.authorizes(0, 1, 42, true));
        assert!(s.authorizes(0, 1, 42, false));
        // A read-only grant authorizes only a read-only reference.
        assert!(!s.authorizes(0, 1, 7, true));
        assert!(s.authorizes(0, 1, 7, false));
        // No permit for the wrong grantee, the wrong frame, or a ghost grantor.
        assert!(!s.authorizes(0, 2, 42, true)); // grantee 2 not named
        assert!(!s.authorizes(0, 1, 99, true)); // frame not granted
        assert!(!s.authorizes(9, 1, 42, true)); // grantor out of range

        // Revoking the grant withdraws the permit.
        s.end_access(0, 0).unwrap();
        assert!(!s.authorizes(0, 1, 42, true));
    }

    #[test]
    fn drain_maps_of_releases_every_mapping_a_domain_holds() {
        let mut s = sys();
        // Domains 0 and 2 each grant a frame to domain 1, which maps both (one
        // writable). Domain 1 also holds nothing of its own here.
        s.grant_access(0, 0, 1, 10, false).unwrap();
        s.grant_access(2, 0, 1, 20, false).unwrap();
        s.map(1, 0, 0, true).unwrap();
        s.map(1, 2, 0, false).unwrap();
        assert_eq!(s.map_count(0, 0), Some(1));
        assert_eq!(s.map_count(2, 0), Some(1));
        assert!(s.holds_any_map(1));

        let released = s.drain_maps_of(1);
        assert_eq!(released.len(), 2, "both mappings drained");
        assert!(released.contains(&Unmapped {
            frame: 10,
            writable: true
        }));
        assert!(released.contains(&Unmapped {
            frame: 20,
            writable: false
        }));
        // The grants those maps stood over now show zero live mappings again.
        assert_eq!(s.map_count(0, 0), Some(0));
        assert_eq!(s.map_count(2, 0), Some(0));
        assert!(
            !s.holds_any_map(1),
            "domain 1 holds nothing after the drain"
        );
        assert!(s.invariants_hold());
    }

    #[test]
    fn revoke_all_ends_every_grant_a_domain_offers() {
        let mut s = sys();
        s.grant_access(0, 0, 1, 1, false).unwrap();
        s.grant_access(0, 3, 2, 2, true).unwrap();
        // A grant offered by a *different* domain must survive domain 0's revoke.
        s.grant_access(1, 0, 0, 3, false).unwrap();
        assert!(s.is_granted(0, 0) && s.is_granted(0, 3) && s.is_granted(1, 0));

        s.revoke_all(0);
        assert!(!s.is_granted(0, 0), "domain 0's grants are gone");
        assert!(!s.is_granted(0, 3));
        assert!(s.is_granted(1, 0), "another domain's grant is untouched");
        assert!(s.invariants_hold());
    }

    #[test]
    fn bad_ids_are_rejected() {
        let mut s = sys();
        assert_eq!(
            s.grant_access(9, 0, 1, 0, false),
            Err(GrantError::BadDomain)
        );
        assert_eq!(
            s.grant_access(0, 99, 1, 0, false),
            Err(GrantError::BadGrantRef)
        );
        assert_eq!(
            s.grant_access(0, 0, 9, 0, false),
            Err(GrantError::BadDomain)
        );
        assert_eq!(s.unmap(0, 123), Err(GrantError::BadHandle));
    }
}
