<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Security policy

Baleen is a research hypervisor whose entire thesis is *safety by construction*: the
pure `hv-core` brain forbids `unsafe`, checks a set of whole-system isolation invariants
after every state transition, and proves them exhaustively with a bounded model checker
on every reachable state of a small configuration. Reports that find a hole in that
model — an isolation or soundness bug the invariants should have caught but do not — are
the most valuable kind and are very welcome.

## Supported versions

Baleen is pre-release (`0.0.0`) and has cut no releases. **Only the `main` branch is
supported**; fixes land there. There is no hardware backend yet (see the README
milestones), so today's surface is the pure state-machine core and its harness.

## Reporting a vulnerability

Please report privately — do **not** open a public issue for a suspected
vulnerability.

Open a [GitHub private security advisory](https://github.com/via-balaena/baleen/security/advisories/new)
("Report a vulnerability" on the repository's **Security** tab). Include enough to
reproduce — ideally a failing seed, a hypercall trace, or an enumerator counterexample.
This keeps the report private to the maintainers until a fix is ready.

Please give us a reasonable window to respond and fix before any public disclosure.
We will acknowledge a report, keep you updated, and credit you in the fix unless you
prefer otherwise.

## What is in scope

- **Isolation / soundness bugs in `hv-core`** — a reachable state that violates a
  documented invariant (cross-domain use-after-free or type confusion, a lost wakeup, an
  unauthorized foreign mapping, a capability outliving its domain, a stale reference
  surviving into a reused domain slot, an off-affinity or double-booked pCPU, …). A
  hypercall sequence reaching such a state is a concrete, reproducible report.
- **Escapes of the model's own assumptions** — a way a transition can mutate state on a
  path the invariant check does not cover, or a `state_key` collision that merges
  distinguishable states and hides coverage.
- **CI / supply-chain weaknesses** — a way to subvert the build, tests, or the pinned
  action set.

## What is out of scope (for now)

- The bare-metal backend, MMU/EPT enforcement, and the guest↔machine address map — these
  live behind the HAL fence and arrive in later milestones (M3+); the core deliberately
  models the accounting, not the hardware.
- Denial of service by a guest against *itself* (an empty affinity mask, a starved vCPU):
  liveness/policy, not an isolation-safety property.
- Wire-format / ABI parsing — the Xen personality (`baleen-xenabi`) is a later milestone.
