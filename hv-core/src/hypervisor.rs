// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The integrated core
//!
//! Everything before this module was a subsystem in isolation: the credit account
//! ([`crate::HvCore`]), event channels ([`crate::evtchn`]), grant tables
//! ([`crate::grant`]). [`Hypervisor`] is the brain that owns all three and routes a
//! single, typed hypercall vocabulary ([`HvCall`]) into them — so `hv-sim` drives
//! one integrated core, and one invariant check ([`Hypervisor::invariants_hold`])
//! covers the whole thing.
//!
//! **This is the dispatch seam, for real.** [`HvCall`] is *ABI-neutral*: it names
//! operations, not wire encodings. At M5 the Xen personality (`baleen-xenabi`)
//! decodes guest register state into an `HvCall` and hands it here — exactly the
//! split flagged back at M1, where the toy `decode` lived in the core only for
//! convenience. The core owns the *operation*; the personality owns the *format*.
//!
//! Each call carries an explicit `caller: DomId` — the domain making the hypercall.
//! The core never trusts a domain to name itself as someone else: `caller` is the
//! acting domain for every routed operation, which is what makes cross-domain
//! permission checks (grant grantee identity, event-channel binding) meaningful.

extern crate alloc;

use alloc::vec::Vec;

use crate::evtchn::{self, Port, Vcpu, Virq};
use crate::grant::{self, Frame, GrantHandle, GrantRef};
use crate::{HError, HvCore};

/// A domain identifier, shared across all subsystems.
pub type DomId = u16;

/// The core's typed, ABI-neutral hypercall vocabulary. A personality decodes a
/// guest's wire-format call into one of these; the core never sees raw registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvCall {
    /// Deposit credits into the caller's account.
    CreditGrant { amount: u32 },
    /// Withdraw credits from the caller's account.
    CreditSpend { amount: u32 },

    /// Allocate a half-open event-channel port awaiting `remote`.
    EvtchnAllocUnbound { remote: DomId },
    /// Bind an event-channel port to `remote`'s waiting `remote_port`.
    EvtchnBindInterdomain { remote: DomId, remote_port: Port },
    /// Bind an event-channel port to a per-vCPU virtual IRQ.
    EvtchnBindVirq { vcpu: Vcpu, virq: Virq },
    /// Bind an event-channel port to a vCPU for IPIs.
    EvtchnBindIpi { vcpu: Vcpu },
    /// Close one of the caller's event-channel ports.
    EvtchnClose { port: Port },
    /// Signal an event-channel port.
    EvtchnSend { port: Port },
    /// Mask an event-channel port.
    EvtchnMask { port: Port },
    /// Unmask an event-channel port.
    EvtchnUnmask { port: Port },
    /// Consume (acknowledge) an event-channel port's pending bit.
    EvtchnConsume { port: Port },

    /// Offer `frame` to `grantee` at the caller's grant slot `gref`.
    GrantAccess {
        gref: GrantRef,
        grantee: DomId,
        frame: Frame,
        readonly: bool,
    },
    /// Revoke one of the caller's grants.
    GrantEndAccess { gref: GrantRef },
    /// Map a grant that `grantor` offered to the caller.
    GrantMap {
        grantor: DomId,
        gref: GrantRef,
        writable: bool,
    },
    /// Unmap one of the caller's mappings.
    GrantUnmap { handle: GrantHandle },
    /// Transient grant-checked copy access (no reference taken).
    GrantCopy {
        grantor: DomId,
        gref: GrantRef,
        write: bool,
    },
}

/// The success value of a routed hypercall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvOutcome {
    /// Completed with no interesting value.
    Done,
    /// A credit balance (credit ops).
    Balance(u64),
    /// A freshly allocated event-channel port.
    Port(Port),
    /// A grant map handle.
    Handle(GrantHandle),
    /// Whether a consumed port had been pending.
    Pending(bool),
}

/// A routed hypercall's failure, tagged by the subsystem that rejected it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvError {
    /// The caller domain id is out of range.
    BadDomain,
    /// The credit subsystem rejected the call.
    Credit(HError),
    /// The event-channel subsystem rejected the call.
    Evtchn(evtchn::EvtchnError),
    /// The grant subsystem rejected the call.
    Grant(grant::GrantError),
}

/// The integrated hypervisor core: per-domain credit plus the two whole-system
/// subsystems, behind one dispatch entry point.
pub struct Hypervisor {
    credit: Vec<HvCore>,
    evtchn: evtchn::System,
    grant: grant::System,
}

impl Hypervisor {
    /// A hypervisor of `num_domains` domains, each with `ports_per_domain`
    /// event-channel ports and `grants_per_domain` grant slots. All three subsystems
    /// share the same domain count.
    pub fn new(num_domains: usize, ports_per_domain: usize, grants_per_domain: usize) -> Self {
        Hypervisor {
            credit: (0..num_domains).map(|_| HvCore::new()).collect(),
            evtchn: evtchn::System::new(num_domains, ports_per_domain),
            grant: grant::System::new(num_domains, grants_per_domain),
        }
    }

    /// Route one hypercall from `caller` to the owning subsystem, with `caller` as
    /// the acting domain throughout. Errors are the subsystem's own, tagged.
    pub fn dispatch(&mut self, caller: DomId, call: HvCall) -> Result<HvOutcome, HvError> {
        match call {
            HvCall::CreditGrant { amount } => self
                .credit_of(caller)?
                .grant_credit(amount)
                .map(HvOutcome::Balance)
                .map_err(HvError::Credit),
            HvCall::CreditSpend { amount } => self
                .credit_of(caller)?
                .spend_credit(amount)
                .map(HvOutcome::Balance)
                .map_err(HvError::Credit),

            HvCall::EvtchnAllocUnbound { remote } => self
                .evtchn
                .alloc_unbound(caller, remote)
                .map(HvOutcome::Port)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnBindInterdomain {
                remote,
                remote_port,
            } => self
                .evtchn
                .bind_interdomain(caller, remote, remote_port)
                .map(HvOutcome::Port)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnBindVirq { vcpu, virq } => self
                .evtchn
                .bind_virq(caller, vcpu, virq)
                .map(HvOutcome::Port)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnBindIpi { vcpu } => self
                .evtchn
                .bind_ipi(caller, vcpu)
                .map(HvOutcome::Port)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnClose { port } => self
                .evtchn
                .close(caller, port)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnSend { port } => self
                .evtchn
                .send(caller, port)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnMask { port } => self
                .evtchn
                .mask(caller, port)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnUnmask { port } => self
                .evtchn
                .unmask(caller, port)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Evtchn),
            HvCall::EvtchnConsume { port } => self
                .evtchn
                .consume(caller, port)
                .map(HvOutcome::Pending)
                .map_err(HvError::Evtchn),

            HvCall::GrantAccess {
                gref,
                grantee,
                frame,
                readonly,
            } => self
                .grant
                .grant_access(caller, gref, grantee, frame, readonly)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Grant),
            HvCall::GrantEndAccess { gref } => self
                .grant
                .end_access(caller, gref)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Grant),
            HvCall::GrantMap {
                grantor,
                gref,
                writable,
            } => self
                .grant
                .map(caller, grantor, gref, writable)
                .map(HvOutcome::Handle)
                .map_err(HvError::Grant),
            HvCall::GrantUnmap { handle } => self
                .grant
                .unmap(caller, handle)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Grant),
            HvCall::GrantCopy {
                grantor,
                gref,
                write,
            } => self
                .grant
                .copy(caller, grantor, gref, write)
                .map(|()| HvOutcome::Done)
                .map_err(HvError::Grant),
        }
    }

    /// Whether every subsystem's invariants hold — the one check that covers the
    /// integrated core. Evaluated in release too.
    pub fn invariants_hold(&self) -> bool {
        self.evtchn.invariants_hold()
            && self.grant.invariants_hold()
            && self.credit.iter().all(HvCore::invariants_hold)
    }

    /// Number of domains.
    pub fn domain_count(&self) -> usize {
        self.credit.len()
    }

    /// A domain's credit balance, if it exists.
    pub fn balance(&self, dom: DomId) -> Option<u64> {
        self.credit.get(dom as usize).map(HvCore::balance)
    }

    /// The event-channel subsystem, for inspection.
    pub fn evtchn(&self) -> &evtchn::System {
        &self.evtchn
    }

    /// The grant subsystem, for inspection.
    pub fn grant(&self) -> &grant::System {
        &self.grant
    }

    fn credit_of(&mut self, dom: DomId) -> Result<&mut HvCore, HvError> {
        self.credit.get_mut(dom as usize).ok_or(HvError::BadDomain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hv() -> Hypervisor {
        Hypervisor::new(3, 8, 6)
    }

    #[test]
    fn credit_routes_to_the_callers_account() {
        let mut h = hv();
        assert_eq!(
            h.dispatch(1, HvCall::CreditGrant { amount: 100 }),
            Ok(HvOutcome::Balance(100))
        );
        // The deposit landed on domain 1, not domain 0.
        assert_eq!(h.balance(0), Some(0));
        assert_eq!(h.balance(1), Some(100));
        assert_eq!(
            h.dispatch(1, HvCall::CreditSpend { amount: 40 }),
            Ok(HvOutcome::Balance(60))
        );
    }

    #[test]
    fn a_full_interdomain_handshake_through_dispatch() {
        let mut h = hv();
        // Domain 1 opens a port for domain 0; domain 0 binds it; domain 0 signals.
        let unbound = match h.dispatch(1, HvCall::EvtchnAllocUnbound { remote: 0 }) {
            Ok(HvOutcome::Port(p)) => p,
            other => panic!("expected a port, got {other:?}"),
        };
        let local = match h.dispatch(
            0,
            HvCall::EvtchnBindInterdomain {
                remote: 1,
                remote_port: unbound,
            },
        ) {
            Ok(HvOutcome::Port(p)) => p,
            other => panic!("expected a port, got {other:?}"),
        };
        h.dispatch(0, HvCall::EvtchnSend { port: local }).unwrap();
        // The peer (domain 1's port) is now pending.
        assert!(h.evtchn().is_pending(1, unbound));
        assert!(h.invariants_hold());
    }

    #[test]
    fn a_full_grant_map_unmap_through_dispatch() {
        let mut h = hv();
        h.dispatch(
            0,
            HvCall::GrantAccess {
                gref: 2,
                grantee: 1,
                frame: 0xABC,
                readonly: false,
            },
        )
        .unwrap();
        let handle = match h.dispatch(
            1,
            HvCall::GrantMap {
                grantor: 0,
                gref: 2,
                writable: true,
            },
        ) {
            Ok(HvOutcome::Handle(x)) => x,
            other => panic!("expected a handle, got {other:?}"),
        };
        // Grantor cannot revoke while domain 1 holds the mapping.
        assert_eq!(
            h.dispatch(0, HvCall::GrantEndAccess { gref: 2 }),
            Err(HvError::Grant(grant::GrantError::InUse))
        );
        h.dispatch(1, HvCall::GrantUnmap { handle }).unwrap();
        assert!(h.dispatch(0, HvCall::GrantEndAccess { gref: 2 }).is_ok());
        assert!(h.invariants_hold());
    }

    #[test]
    fn errors_are_tagged_by_subsystem() {
        let mut h = hv();
        assert_eq!(
            h.dispatch(9, HvCall::CreditGrant { amount: 1 }),
            Err(HvError::BadDomain)
        );
        assert_eq!(
            h.dispatch(0, HvCall::EvtchnSend { port: 0 }),
            Err(HvError::Evtchn(evtchn::EvtchnError::WrongState))
        );
        assert_eq!(
            h.dispatch(
                0,
                HvCall::GrantMap {
                    grantor: 1,
                    gref: 0,
                    writable: false
                }
            ),
            Err(HvError::Grant(grant::GrantError::WrongState))
        );
    }
}
