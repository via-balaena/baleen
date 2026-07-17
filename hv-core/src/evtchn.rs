// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Event channels — a pure, whole-system state machine
//!
//! Event channels are the hypervisor's lightweight async notification primitive: a
//! per-domain *port* that can be bound to a peer in another domain, to a per-vCPU
//! virtual IRQ, or to a vCPU for IPIs, and then *signalled* (a pending bit set).
//! This has historically been an XSA factory in Xen — the bugs are subtle lifecycle
//! and reciprocity errors — so the invariant is the point of this module.
//!
//! **Whole-system model.** The state is *all* domains' port tables in one
//! [`System`], not a single domain with opaque remote references. That is the only
//! way the headline invariant — interdomain *reciprocity* — can be self-checked:
//! both ends of a channel are visible at once.
//!
//! **What lives here vs. what does not.** The core owns the abstract lifecycle and
//! the signal bits (`pending`, `masked`). It does *not* own port *numbering* or the
//! wire layout (Xen's two-level `shared_info` bitmaps, or the FIFO ABI) — those are
//! a *personality* concern and arrive with `baleen-xenabi` at M5. And delivery is
//! the fence again: the core *decides* deliverability ([`System::deliverable`] =
//! `pending && !masked`); the HAL ([`hv_hal::VcpuOps::inject_interrupt`]) *does* the
//! upcall. Core decides, metal translates.
//!
//! Provenance: designed from the public Xen event-channel ABI semantics and general
//! OS knowledge (the abstract lifecycle and the reciprocity rule) — not `xen/`'s GPL
//! implementation. See `CLEANROOM.md`.

extern crate alloc;

use alloc::vec::Vec;

/// A domain identifier — an index into the [`System`]'s domain table.
pub type DomId = u16;
/// A port identifier — an index into a domain's port table.
///
/// A bare slot index, reclaimed by [`System::close`] and re-handed by the next
/// bind. A stale port number therefore names whatever binding later reused the slot
/// (there is no generation counter). Because a domain only ever operates on its own
/// ports, this can confuse a domain with *itself* but never crosses a domain
/// boundary; guests must not reuse closed ports, as in Xen.
pub type Port = u32;
/// A virtual CPU identifier, scoped to a domain.
pub type Vcpu = u32;
/// A virtual IRQ number, scoped to a (domain, vCPU).
pub type Virq = u8;

/// What a port *is*. Exactly one variant at any time — that totality is the first
/// invariant, and it is why binding always starts from [`PortState::Free`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// Not allocated.
    Free,
    /// Allocated and waiting for domain `remote` to bind the interdomain peer.
    /// Half-open: it holds no reciprocal link yet.
    Unbound { remote: DomId },
    /// Connected to `(remote, remote_port)`. The peer port MUST point back at this
    /// one — that reciprocity is the headline invariant.
    Interdomain { remote: DomId, remote_port: Port },
    /// Bound to a per-vCPU virtual IRQ. Unique per `(vcpu, virq)` within a domain.
    Virq { vcpu: Vcpu, virq: Virq },
    /// Bound to a vCPU for intra-domain inter-processor interrupts.
    Ipi { vcpu: Vcpu },
}

/// A port's state plus its two signal bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EventChannel {
    state: PortState,
    pending: bool,
    masked: bool,
}

impl EventChannel {
    const FREE: Self = EventChannel {
        state: PortState::Free,
        pending: false,
        masked: false,
    };
}

/// One domain's fixed-size port table.
struct Domain {
    ports: Vec<EventChannel>,
}

/// The whole-system event-channel state — every domain's ports in one place, so the
/// reciprocity invariant is checkable after every transition.
pub struct System {
    domains: Vec<Domain>,
}

/// Why a transition was rejected. Rejections leave the system unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvtchnError {
    /// The domain id is out of range.
    BadDomain,
    /// The port id is out of range for its domain.
    BadPort,
    /// The domain's port table is full.
    NoFreePort,
    /// The port was not in a state this operation accepts (e.g. binding an
    /// interdomain peer that is not `Unbound` for the requesting domain, or sending
    /// on a `Virq`/`Free` port).
    WrongState,
    /// That `(vcpu, virq)` is already bound in this domain.
    VirqInUse,
}

/// A named invariant breach, carrying the port it was found at. Returned by
/// [`System::first_violation`] so both the debug-time assert and the release-time
/// property tests report the *same* structured cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// A `Free` port still carries a `pending` or `masked` bit.
    FreePortHasSignal { dom: usize, port: usize },
    /// An `Interdomain` port's peer does not point back at it.
    ReciprocityBroken { dom: usize, port: usize },
    /// An `Unbound` port names a domain that does not exist.
    UnboundGhostDomain { dom: usize, port: usize },
    /// Two ports in one domain bind the same `(vcpu, virq)`.
    DuplicateVirq { dom: usize, port: usize },
}

impl System {
    /// A system of `num_domains` domains, each with `ports_per_domain` free ports.
    pub fn new(num_domains: usize, ports_per_domain: usize) -> Self {
        let make_domain = || Domain {
            ports: (0..ports_per_domain).map(|_| EventChannel::FREE).collect(),
        };
        System {
            domains: (0..num_domains).map(|_| make_domain()).collect(),
        }
    }

    // ─── transitions ─────────────────────────────────────────────────────────

    /// Allocate a half-open port in `dom`, waiting for `remote` to bind the peer.
    pub fn alloc_unbound(&mut self, dom: DomId, remote: DomId) -> Result<Port, EvtchnError> {
        // The binder-to-be must be a real domain, so the port names no ghost.
        self.domain(remote)?;
        let port = self.find_free(dom)?;
        self.chan_mut(dom, port).unwrap().state = PortState::Unbound { remote };
        self.check_invariants();
        Ok(port)
    }

    /// Bind a fresh port in `dom` to `remote`'s `remote_port`, which must currently
    /// be `Unbound` *and* expecting `dom`. Establishes both ends reciprocally.
    pub fn bind_interdomain(
        &mut self,
        dom: DomId,
        remote: DomId,
        remote_port: Port,
    ) -> Result<Port, EvtchnError> {
        // The peer must be half-open and waiting for exactly us — no hijacking a
        // port that was opened for someone else.
        match self.chan(remote, remote_port)?.state {
            PortState::Unbound { remote: expected } if expected == dom => {}
            _ => return Err(EvtchnError::WrongState),
        }
        // Allocate our end only after the peer check passes; nothing is mutated on
        // any error path, so a failed bind is a true no-op.
        let port = self.find_free(dom)?;
        // Overwrite the whole channel on both ends, not just `.state`: a fresh
        // channel starts clean, clearing any `masked` bit the peer's domain may have
        // set while it sat `Unbound` (otherwise the channel would be born masked).
        *self.chan_mut(dom, port).unwrap() = EventChannel {
            state: PortState::Interdomain {
                remote,
                remote_port,
            },
            pending: false,
            masked: false,
        };
        *self.chan_mut(remote, remote_port).unwrap() = EventChannel {
            state: PortState::Interdomain {
                remote: dom,
                remote_port: port,
            },
            pending: false,
            masked: false,
        };
        self.check_invariants();
        Ok(port)
    }

    /// Bind a fresh port in `dom` to `(vcpu, virq)`. That pair must not already be
    /// bound in this domain.
    pub fn bind_virq(&mut self, dom: DomId, vcpu: Vcpu, virq: Virq) -> Result<Port, EvtchnError> {
        let d = self.domain(dom)?;
        let in_use = d.ports.iter().any(
            |c| matches!(c.state, PortState::Virq { vcpu: v, virq: q } if v == vcpu && q == virq),
        );
        if in_use {
            return Err(EvtchnError::VirqInUse);
        }
        let port = self.find_free(dom)?;
        self.chan_mut(dom, port).unwrap().state = PortState::Virq { vcpu, virq };
        self.check_invariants();
        Ok(port)
    }

    /// Bind a fresh port in `dom` to `vcpu` for IPIs.
    pub fn bind_ipi(&mut self, dom: DomId, vcpu: Vcpu) -> Result<Port, EvtchnError> {
        let port = self.find_free(dom)?;
        self.chan_mut(dom, port).unwrap().state = PortState::Ipi { vcpu };
        self.check_invariants();
        Ok(port)
    }

    /// Close a bound port. If it is interdomain, the peer is returned to `Unbound`
    /// (pointing back at us) so it can be re-bound — it is *not* destroyed. This is
    /// where use-after-free / reciprocity bugs classically hide.
    pub fn close(&mut self, dom: DomId, port: Port) -> Result<(), EvtchnError> {
        match self.chan(dom, port)?.state {
            PortState::Free => return Err(EvtchnError::WrongState),
            PortState::Interdomain {
                remote,
                remote_port,
            } => {
                // The peer index is always valid while the link exists (upheld by
                // the reciprocity invariant), and is never this same port.
                let peer = self.chan_mut(remote, remote_port).unwrap();
                peer.state = PortState::Unbound { remote: dom };
                peer.pending = false;
                peer.masked = false;
            }
            _ => {}
        }
        let ch = self.chan_mut(dom, port).unwrap();
        *ch = EventChannel::FREE;
        self.check_invariants();
        Ok(())
    }

    /// Signal a port: set the `pending` bit on its *target*. For an interdomain port
    /// the target is the peer; for an IPI it is the port itself. `Unbound`, `Virq`,
    /// and `Free` ports cannot be sent by a guest.
    pub fn send(&mut self, dom: DomId, port: Port) -> Result<(), EvtchnError> {
        // Validate the source ids with precise errors first, then resolve the target
        // from its state — the same rule [`Self::send_target`] exposes to the seam.
        self.chan(dom, port)?;
        let (target_dom, target_port) =
            self.send_target(dom, port).ok_or(EvtchnError::WrongState)?;
        self.chan_mut(target_dom, target_port).unwrap().pending = true;
        self.check_invariants();
        Ok(())
    }

    /// The `(dom, port)` a [`Self::send`] on this port would signal: the peer for an
    /// `Interdomain` port, the port itself for an `Ipi`. `None` for a port a guest
    /// cannot send on (`Unbound`, `Virq`, `Free`) — the same states `send` rejects
    /// with `WrongState`. The single source of the target rule, shared by `send` and
    /// read by [`crate::Hypervisor`] so a signal can wake whoever it just made pending.
    pub fn send_target(&self, dom: DomId, port: Port) -> Option<(DomId, Port)> {
        match self.chan(dom, port).ok()?.state {
            PortState::Interdomain {
                remote,
                remote_port,
            } => Some((remote, remote_port)),
            PortState::Ipi { .. } => Some((dom, port)),
            _ => None,
        }
    }

    /// Mask a bound port (suppresses delivery, not the pending bit).
    pub fn mask(&mut self, dom: DomId, port: Port) -> Result<(), EvtchnError> {
        self.set_masked(dom, port, true)
    }

    /// Unmask a bound port.
    pub fn unmask(&mut self, dom: DomId, port: Port) -> Result<(), EvtchnError> {
        self.set_masked(dom, port, false)
    }

    /// Consume a port's pending bit (the guest acknowledging the event). Returns
    /// whether it had been pending.
    pub fn consume(&mut self, dom: DomId, port: Port) -> Result<bool, EvtchnError> {
        let ch = self.chan_mut(dom, port)?;
        if ch.state == PortState::Free {
            return Err(EvtchnError::WrongState);
        }
        let was_pending = ch.pending;
        ch.pending = false;
        self.check_invariants();
        Ok(was_pending)
    }

    // ─── queries (the read side of the fence) ─────────────────────────────────

    /// Whether an event on this port would be delivered *now*: pending and not
    /// masked. The core decides this; the HAL performs the injection.
    pub fn deliverable(&self, dom: DomId, port: Port) -> bool {
        self.chan(dom, port)
            .map(|c| c.pending && !c.masked)
            .unwrap_or(false)
    }

    /// The vCPU (within this port's own domain) that a delivery on this port should
    /// wake — the notify target. Derived purely from the binding, so no per-port
    /// field is stored:
    ///
    /// - a `Virq { vcpu, .. }` or `Ipi { vcpu }` port targets its bound `vcpu`;
    /// - an `Interdomain` or `Unbound` port targets vCPU 0, Xen's default
    ///   `notify_vcpu_id`. Steering it elsewhere (Xen's `EVTCHNOP_bind_vcpu`) is a
    ///   later refinement with no safety content, so the default stands for now;
    /// - a `Free` port targets nothing.
    ///
    /// This is the read half of the event→scheduler seam: [`crate::Hypervisor`] wakes
    /// `(dom, notify_target)` when a port here becomes deliverable. The core names the
    /// target; the seam moves the scheduler.
    pub fn notify_target(&self, dom: DomId, port: Port) -> Option<Vcpu> {
        match self.chan(dom, port).ok()?.state {
            PortState::Virq { vcpu, .. } | PortState::Ipi { vcpu } => Some(vcpu),
            PortState::Interdomain { .. } | PortState::Unbound { .. } => Some(0),
            PortState::Free => None,
        }
    }

    /// Whether `vcpu` has any *deliverable* event waiting on one of `dom`'s ports —
    /// a port that is pending, unmasked, and notify-targets this vCPU. The seam uses
    /// this to refuse to let a vCPU block with work already pending (the lost-wakeup
    /// race), and the cross-invariant uses it from the other side.
    pub fn has_deliverable_for(&self, dom: DomId, vcpu: Vcpu) -> bool {
        (0..self.port_count(dom) as Port)
            .any(|port| self.deliverable(dom, port) && self.notify_target(dom, port) == Some(vcpu))
    }

    /// The state of a port, if the ids are in range.
    pub fn state_of(&self, dom: DomId, port: Port) -> Option<PortState> {
        self.chan(dom, port).ok().map(|c| c.state)
    }

    /// Whether a port's pending bit is set.
    pub fn is_pending(&self, dom: DomId, port: Port) -> bool {
        self.chan(dom, port).map(|c| c.pending).unwrap_or(false)
    }

    /// Whether a port is masked.
    pub fn is_masked(&self, dom: DomId, port: Port) -> bool {
        self.chan(dom, port).map(|c| c.masked).unwrap_or(false)
    }

    /// Number of domains.
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Number of ports in a domain (0 if the domain id is out of range).
    pub fn port_count(&self, dom: DomId) -> usize {
        self.domain(dom).map(|d| d.ports.len()).unwrap_or(0)
    }

    // ─── invariants ───────────────────────────────────────────────────────────

    /// The first invariant breach found, or `None` if the system is consistent.
    /// This is the single source of truth for correctness, used both by the
    /// debug-time invariant assertion and by release-mode property tests.
    pub fn first_violation(&self) -> Option<Violation> {
        for (d, dom) in self.domains.iter().enumerate() {
            for (p, ec) in dom.ports.iter().enumerate() {
                match ec.state {
                    PortState::Free => {
                        if ec.pending || ec.masked {
                            return Some(Violation::FreePortHasSignal { dom: d, port: p });
                        }
                    }
                    PortState::Interdomain {
                        remote,
                        remote_port,
                    } => {
                        let peer = self
                            .domains
                            .get(remote as usize)
                            .and_then(|dd| dd.ports.get(remote_port as usize))
                            .map(|c| c.state);
                        let reciprocal = matches!(
                            peer,
                            Some(PortState::Interdomain { remote: r, remote_port: q })
                                if r as usize == d && q as usize == p
                        );
                        if !reciprocal {
                            return Some(Violation::ReciprocityBroken { dom: d, port: p });
                        }
                    }
                    PortState::Unbound { remote } => {
                        if remote as usize >= self.domains.len() {
                            return Some(Violation::UnboundGhostDomain { dom: d, port: p });
                        }
                    }
                    PortState::Virq { vcpu, virq } => {
                        let duplicate = dom.ports.iter().enumerate().any(|(q, e)| {
                            q != p
                                && matches!(e.state, PortState::Virq { vcpu: v, virq: vq }
                                    if v == vcpu && vq == virq)
                        });
                        if duplicate {
                            return Some(Violation::DuplicateVirq { dom: d, port: p });
                        }
                    }
                    PortState::Ipi { .. } => {}
                }
            }
        }
        None
    }

    /// Whether every invariant holds. Always evaluated (unlike the debug assert), so
    /// tests can assert it in release builds too.
    pub fn invariants_hold(&self) -> bool {
        self.first_violation().is_none()
    }

    /// Assert the invariants — compiled out in release, so it is free on the metal
    /// yet hit by every seeded interleaving under test.
    fn check_invariants(&self) {
        debug_assert!(
            self.first_violation().is_none(),
            "event-channel invariant violated: {:?}",
            self.first_violation()
        );
    }

    // ─── internals ────────────────────────────────────────────────────────────

    fn set_masked(&mut self, dom: DomId, port: Port, value: bool) -> Result<(), EvtchnError> {
        let ch = self.chan_mut(dom, port)?;
        if ch.state == PortState::Free {
            return Err(EvtchnError::WrongState);
        }
        ch.masked = value;
        self.check_invariants();
        Ok(())
    }

    fn find_free(&self, dom: DomId) -> Result<Port, EvtchnError> {
        let d = self.domain(dom)?;
        d.ports
            .iter()
            .position(|c| c.state == PortState::Free)
            .map(|i| i as Port)
            .ok_or(EvtchnError::NoFreePort)
    }

    fn domain(&self, dom: DomId) -> Result<&Domain, EvtchnError> {
        self.domains.get(dom as usize).ok_or(EvtchnError::BadDomain)
    }

    fn domain_mut(&mut self, dom: DomId) -> Result<&mut Domain, EvtchnError> {
        self.domains
            .get_mut(dom as usize)
            .ok_or(EvtchnError::BadDomain)
    }

    fn chan(&self, dom: DomId, port: Port) -> Result<&EventChannel, EvtchnError> {
        self.domain(dom)?
            .ports
            .get(port as usize)
            .ok_or(EvtchnError::BadPort)
    }

    fn chan_mut(&mut self, dom: DomId, port: Port) -> Result<&mut EventChannel, EvtchnError> {
        self.domain_mut(dom)?
            .ports
            .get_mut(port as usize)
            .ok_or(EvtchnError::BadPort)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A 3-domain system with 8 ports each — enough to exercise every transition.
    fn sys() -> System {
        System::new(3, 8)
    }

    #[test]
    fn alloc_then_bind_is_reciprocal() {
        let mut s = sys();
        let unbound = s.alloc_unbound(1, 0).unwrap();
        let local = s.bind_interdomain(0, 1, unbound).unwrap();
        assert_eq!(
            s.state_of(0, local),
            Some(PortState::Interdomain {
                remote: 1,
                remote_port: unbound
            })
        );
        assert_eq!(
            s.state_of(1, unbound),
            Some(PortState::Interdomain {
                remote: 0,
                remote_port: local
            })
        );
        assert!(s.invariants_hold());
    }

    #[test]
    fn bind_rejects_a_port_not_waiting_for_us() {
        let mut s = sys();
        // Domain 1 opens a port waiting for domain 0, but domain 2 tries to grab it.
        let unbound = s.alloc_unbound(1, 0).unwrap();
        assert_eq!(
            s.bind_interdomain(2, 1, unbound),
            Err(EvtchnError::WrongState)
        );
        // The unbound port is untouched.
        assert_eq!(
            s.state_of(1, unbound),
            Some(PortState::Unbound { remote: 0 })
        );
    }

    #[test]
    fn close_returns_peer_to_unbound_and_rebindable() {
        let mut s = sys();
        let unbound = s.alloc_unbound(1, 0).unwrap();
        let local = s.bind_interdomain(0, 1, unbound).unwrap();

        s.close(0, local).unwrap();
        // Our end is free; the peer is half-open again, pointing back at us.
        assert_eq!(s.state_of(0, local), Some(PortState::Free));
        assert_eq!(
            s.state_of(1, unbound),
            Some(PortState::Unbound { remote: 0 })
        );
        assert!(s.invariants_hold());

        // And it can be re-bound — no dangling link left behind.
        let again = s.bind_interdomain(0, 1, unbound).unwrap();
        assert_eq!(
            s.state_of(1, unbound),
            Some(PortState::Interdomain {
                remote: 0,
                remote_port: again
            })
        );
    }

    #[test]
    fn send_sets_pending_on_the_peer_not_the_sender() {
        let mut s = sys();
        let unbound = s.alloc_unbound(1, 0).unwrap();
        let local = s.bind_interdomain(0, 1, unbound).unwrap();

        s.send(0, local).unwrap();
        assert!(
            !s.is_pending(0, local),
            "sender's own port must not go pending"
        );
        assert!(s.is_pending(1, unbound), "peer must go pending");
    }

    #[test]
    fn masked_target_is_pending_but_not_deliverable() {
        let mut s = sys();
        let unbound = s.alloc_unbound(1, 0).unwrap();
        let local = s.bind_interdomain(0, 1, unbound).unwrap();

        s.mask(1, unbound).unwrap();
        s.send(0, local).unwrap();
        assert!(s.is_pending(1, unbound));
        assert!(
            !s.deliverable(1, unbound),
            "masked channel must not deliver"
        );

        s.unmask(1, unbound).unwrap();
        assert!(
            s.deliverable(1, unbound),
            "unmasking a pending channel delivers"
        );
    }

    #[test]
    fn virq_binding_is_unique_per_pair() {
        let mut s = sys();
        s.bind_virq(0, 0, 3).unwrap();
        assert_eq!(s.bind_virq(0, 0, 3), Err(EvtchnError::VirqInUse));
        // A different vCPU or virq is fine.
        assert!(s.bind_virq(0, 1, 3).is_ok());
        assert!(s.bind_virq(0, 0, 4).is_ok());
    }

    #[test]
    fn ipi_sends_to_itself() {
        let mut s = sys();
        let p = s.bind_ipi(0, 0).unwrap();
        s.send(0, p).unwrap();
        assert!(s.is_pending(0, p));
    }

    #[test]
    fn cannot_send_on_virq_or_free() {
        let mut s = sys();
        let v = s.bind_virq(0, 0, 1).unwrap();
        assert_eq!(s.send(0, v), Err(EvtchnError::WrongState));
        assert_eq!(s.send(0, 7), Err(EvtchnError::WrongState)); // a free port
    }

    #[test]
    fn full_table_reports_no_free_port() {
        let mut s = System::new(1, 2);
        s.bind_ipi(0, 0).unwrap();
        s.bind_ipi(0, 0).unwrap();
        assert_eq!(s.bind_ipi(0, 0), Err(EvtchnError::NoFreePort));
    }

    #[test]
    fn bad_ids_are_rejected() {
        let mut s = sys();
        assert_eq!(s.alloc_unbound(9, 0), Err(EvtchnError::BadDomain));
        assert_eq!(s.send(0, 99), Err(EvtchnError::BadPort));
    }

    #[test]
    fn a_bound_channel_starts_unmasked_even_if_the_unbound_port_was_masked() {
        let mut s = sys();
        let unbound = s.alloc_unbound(1, 0).unwrap();
        // Domain 1 masks its port while it is still half-open.
        s.mask(1, unbound).unwrap();
        assert!(s.is_masked(1, unbound));

        // Binding forms a fresh channel — the stale mask must not carry over.
        let local = s.bind_interdomain(0, 1, unbound).unwrap();
        assert!(!s.is_masked(1, unbound), "bound channel was born masked");

        s.send(0, local).unwrap();
        assert!(s.deliverable(1, unbound), "fresh channel should deliver");
    }

    #[test]
    fn notify_target_follows_the_binding() {
        let mut s = sys();
        // VIRQ and IPI ports target their bound vCPU.
        let v = s.bind_virq(0, 3, 1).unwrap();
        assert_eq!(s.notify_target(0, v), Some(3));
        let i = s.bind_ipi(0, 2).unwrap();
        assert_eq!(s.notify_target(0, i), Some(2));
        // Interdomain and unbound ports default to vCPU 0.
        let unbound = s.alloc_unbound(1, 0).unwrap();
        assert_eq!(s.notify_target(1, unbound), Some(0));
        let local = s.bind_interdomain(0, 1, unbound).unwrap();
        assert_eq!(s.notify_target(0, local), Some(0));
        assert_eq!(s.notify_target(1, unbound), Some(0));
        // A free port targets nothing.
        assert_eq!(s.notify_target(0, 7), None);
    }

    #[test]
    fn has_deliverable_for_tracks_pending_unmasked_targets() {
        let mut s = sys();
        // An IPI port on vCPU 1, not yet signalled: nothing deliverable for anyone.
        let p = s.bind_ipi(0, 1).unwrap();
        assert!(!s.has_deliverable_for(0, 1));
        // Signal it — now vCPU 1 (its target) has a deliverable event, but vCPU 0 does not.
        s.send(0, p).unwrap();
        assert!(s.has_deliverable_for(0, 1));
        assert!(!s.has_deliverable_for(0, 0));
        // Masking suppresses deliverability without clearing pending: not deliverable.
        s.mask(0, p).unwrap();
        assert!(!s.has_deliverable_for(0, 1));
        // Unmasking restores it; consuming the pending bit clears it for good.
        s.unmask(0, p).unwrap();
        assert!(s.has_deliverable_for(0, 1));
        s.consume(0, p).unwrap();
        assert!(!s.has_deliverable_for(0, 1));
    }

    #[test]
    fn same_domain_loopback_is_reciprocal() {
        // A domain may bind an interdomain channel to itself.
        let mut s = sys();
        let a = s.alloc_unbound(0, 0).unwrap();
        let b = s.bind_interdomain(0, 0, a).unwrap();
        assert_ne!(a, b);
        assert!(s.invariants_hold());
        s.send(0, b).unwrap();
        assert!(s.is_pending(0, a));
    }
}
