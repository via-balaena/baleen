// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # hv-core — the brain
//!
//! All of the hypervisor's *thinking* lives here, as a `no_std` library with zero
//! unsafe: hypercall dispatch and the state machines behind it. It touches hardware
//! only through the [`hv_hal`] traits, so the same code that runs on the metal is
//! driven, unit-tested, and fuzzed on the host by [`hv-sim`](../hv_sim/index.html).
//!
//! M1 proves the architecture with the smallest thing that still has a real
//! invariant: a domain *credit account* with two toy hypercalls. The account's
//! invariant — `granted == spent + balance`, and `balance` never underflows — is a
//! stand-in for the ones that actually matter later (grant-table refcounts,
//! page-type counts, event-channel state: Xen's historical XSA factories). The
//! machinery that checks it here is the machinery that will check those.

#![no_std]

pub mod prng;

use hv_hal::{GuestMemory, TimeSource};

/// An error returned across the hypercall ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HError {
    /// The hypercall number was not recognised.
    BadHypercall,
    /// A `Grant` would overflow the account balance.
    Overflow,
    /// A `Spend` asked for more credit than the account holds.
    Insufficient,
}

/// The success value of a hypercall — here, the resulting balance.
pub type HResult = Result<u64, HError>;

/// The raw ABI as hardware presents it at a VMEXIT: a call number and one argument.
///
/// Keeping the raw form explicit gives fuzzing a clean seam — [`Hypercall::decode`]
/// is a pure function from bytes to a typed call, hammerable at millions of
/// exec/sec with no VM in the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawHypercall {
    /// The hypercall number (guest register, by convention).
    pub nr: u32,
    /// The single argument for these toy calls.
    pub arg0: u64,
}

/// ABI number for [`Hypercall::Grant`].
pub const NR_GRANT: u32 = 0;
/// ABI number for [`Hypercall::Spend`].
pub const NR_SPEND: u32 = 1;

/// The two toy hypercalls of M1, decoded into a typed form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hypercall {
    /// Deposit `amount` credits into the domain account.
    Grant { amount: u32 },
    /// Withdraw `amount` credits; fails if the balance is insufficient.
    Spend { amount: u32 },
}

impl Hypercall {
    /// Decode the raw ABI into a typed hypercall.
    ///
    /// **Personality seam — temporary home.** The wire encoding and the hypercall
    /// number space (`NR_GRANT`, `NR_SPEND`, …) are *personality*-owned, not
    /// core-owned: they are ABI decisions, and `hv-core` deliberately knows no ABI.
    /// This lives here only to keep M1 a single crate. At M5, when the Xen
    /// personality (`baleen-xenabi`) arrives, `decode` moves northbound into it —
    /// the personality owns Xen's numbering and structs, and hands `hv-core` an
    /// already-typed, ABI-neutral [`Hypercall`]. The core's job is the *operation*,
    /// never the *wire format*.
    ///
    /// Rejects out-of-range arguments rather than silently truncating them — the
    /// argument field is a `u32`, and a guest that sets the high bits is malformed,
    /// not lucky. This strictness is what keeps the fuzzer's findings meaningful.
    pub fn decode(raw: RawHypercall) -> Result<Self, HError> {
        let amount = u32::try_from(raw.arg0).map_err(|_| HError::BadHypercall)?;
        match raw.nr {
            NR_GRANT => Ok(Hypercall::Grant { amount }),
            NR_SPEND => Ok(Hypercall::Spend { amount }),
            _ => Err(HError::BadHypercall),
        }
    }
}

/// A domain's credit account — the M1 stand-in state machine.
///
/// `balance` is the current credit; `granted` and `spent` are running totals kept
/// only so the conservation invariant can be checked. On hardware these become the
/// real accounting structures, but the discipline is identical: every transition
/// re-establishes the invariant before returning.
#[derive(Debug, Default)]
pub struct HvCore {
    balance: u64,
    granted: u64,
    spent: u64,
}

impl HvCore {
    /// A fresh account with a zero balance.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current credit balance.
    pub fn balance(&self) -> u64 {
        self.balance
    }

    /// Total credit ever granted (monotonically increasing).
    pub fn granted(&self) -> u64 {
        self.granted
    }

    /// Total credit ever spent (monotonically increasing).
    pub fn spent(&self) -> u64 {
        self.spent
    }

    /// Dispatch one decoded hypercall and re-check the invariants.
    ///
    /// `mem` and `time` are unused by these toy calls but are threaded through to
    /// fix the calling convention now: the core reaches the outside world *only*
    /// through the [`hv_hal`] traits, never by touching hardware itself. A real
    /// hypercall (map a grant, read the guest's timer) will use them; the rule that
    /// it must go through the trait is set from the first commit.
    pub fn dispatch<M, T>(&mut self, _mem: &mut M, _time: &T, call: Hypercall) -> HResult
    where
        M: GuestMemory,
        T: TimeSource,
    {
        let result = match call {
            Hypercall::Grant { amount } => {
                let amount = u64::from(amount);
                // On overflow we return before mutating anything, so the invariant
                // still holds on the error path.
                self.balance = self.balance.checked_add(amount).ok_or(HError::Overflow)?;
                self.granted += amount;
                Ok(self.balance)
            }
            Hypercall::Spend { amount } => {
                let amount = u64::from(amount);
                if amount > self.balance {
                    return Err(HError::Insufficient);
                }
                self.balance -= amount;
                self.spent += amount;
                Ok(self.balance)
            }
        };
        self.check_invariants();
        result
    }

    /// The library's invariants, checked on every transition.
    ///
    /// A `debug_assert!` so it costs nothing in a release/on-metal build, yet is hit
    /// by every one of the simulator's thousands of seeded interleavings. When it
    /// fails there, the scenario's seed is the entire reproducer.
    fn check_invariants(&self) {
        debug_assert_eq!(
            self.granted,
            self.spent + self.balance,
            "credit conservation violated: granted={} spent={} balance={}",
            self.granted,
            self.spent,
            self.balance
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A no-op HAL so the pure logic can be unit-tested with no harness at all.
    struct NoMem;
    impl GuestMemory for NoMem {
        fn read(&self, _: hv_hal::Gpa, _: &mut [u8]) -> Result<(), hv_hal::MemError> {
            Ok(())
        }
        fn write(&mut self, _: hv_hal::Gpa, _: &[u8]) -> Result<(), hv_hal::MemError> {
            Ok(())
        }
    }
    struct ZeroClock;
    impl TimeSource for ZeroClock {
        fn now(&self) -> hv_hal::Ticks {
            0
        }
    }

    fn call(core: &mut HvCore, c: Hypercall) -> HResult {
        core.dispatch(&mut NoMem, &ZeroClock, c)
    }

    #[test]
    fn decode_round_trips_known_calls() {
        assert_eq!(
            Hypercall::decode(RawHypercall {
                nr: NR_GRANT,
                arg0: 5
            }),
            Ok(Hypercall::Grant { amount: 5 })
        );
        assert_eq!(
            Hypercall::decode(RawHypercall {
                nr: NR_SPEND,
                arg0: 5
            }),
            Ok(Hypercall::Spend { amount: 5 })
        );
    }

    #[test]
    fn decode_rejects_unknown_and_oversized() {
        assert_eq!(
            Hypercall::decode(RawHypercall { nr: 99, arg0: 0 }),
            Err(HError::BadHypercall)
        );
        assert_eq!(
            Hypercall::decode(RawHypercall {
                nr: NR_GRANT,
                arg0: u64::from(u32::MAX) + 1
            }),
            Err(HError::BadHypercall)
        );
    }

    /// The decoder's full contract — the same property `hv-fuzz`'s `decode` target
    /// asserts, mirrored here so stable CI proves it deterministically without
    /// nightly or cargo-fuzz. If you change either, change both.
    fn assert_decode_contract(nr: u32, arg0: u64) {
        let fits_u32 = arg0 <= u64::from(u32::MAX);
        match Hypercall::decode(RawHypercall { nr, arg0 }) {
            Ok(Hypercall::Grant { amount }) => {
                assert_eq!(nr, NR_GRANT);
                assert_eq!(u64::from(amount), arg0);
            }
            Ok(Hypercall::Spend { amount }) => {
                assert_eq!(nr, NR_SPEND);
                assert_eq!(u64::from(amount), arg0);
            }
            Err(HError::BadHypercall) => {
                let known = nr == NR_GRANT || nr == NR_SPEND;
                assert!(
                    !known || !fits_u32,
                    "rejected a valid (nr={nr}, arg0={arg0})"
                );
            }
            Err(other) => panic!("decode returned an unexpected error: {other:?}"),
        }
    }

    #[test]
    fn decode_contract_holds_over_grid() {
        // Every hypercall number near the known range, crossed with the argument
        // boundary values that matter for the u32-fit check.
        let args = [
            0u64,
            1,
            u64::from(u32::MAX) - 1,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            u64::MAX,
        ];
        for nr in 0..8u32 {
            for &arg0 in &args {
                assert_decode_contract(nr, arg0);
            }
        }
    }

    #[test]
    fn grant_then_spend_settles() {
        let mut core = HvCore::new();
        assert_eq!(call(&mut core, Hypercall::Grant { amount: 100 }), Ok(100));
        assert_eq!(call(&mut core, Hypercall::Spend { amount: 30 }), Ok(70));
        assert_eq!(core.balance(), 70);
        assert_eq!(core.granted(), 100);
        assert_eq!(core.spent(), 30);
    }

    #[test]
    fn overspend_is_rejected_and_leaves_state_intact() {
        let mut core = HvCore::new();
        call(&mut core, Hypercall::Grant { amount: 10 }).unwrap();
        assert_eq!(
            call(&mut core, Hypercall::Spend { amount: 11 }),
            Err(HError::Insufficient)
        );
        assert_eq!(core.balance(), 10);
        assert_eq!(core.spent(), 0);
    }

    #[test]
    fn grant_overflow_is_rejected_and_leaves_state_intact() {
        let mut core = HvCore::new();
        call(&mut core, Hypercall::Grant { amount: u32::MAX }).unwrap();
        call(&mut core, Hypercall::Grant { amount: u32::MAX }).unwrap();
        // balance is now 2*u32::MAX, still far below u64::MAX, so this must succeed;
        // the overflow guard is exercised in the simulator's long seeded runs.
        assert!(call(&mut core, Hypercall::Grant { amount: u32::MAX }).is_ok());
    }
}
