// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Baleen's task runner. Invoke as `cargo xtask <task>` (see `.cargo/config.toml`).
//!
//! Deliberately tiny for M1 — it grows to cover `hv-metal` cross-builds and the
//! `hv-fuzz` targets as those milestones land.

use std::process::{exit, Command};

fn main() {
    let task = std::env::args().nth(1).unwrap_or_default();
    let ok = match task.as_str() {
        "test" => run("cargo", &["test", "--workspace"]),
        "check" => run("cargo", &["check", "--workspace"]),
        "ci" => {
            run("cargo", &["fmt", "--all", "--", "--check"])
                && run("cargo", &["clippy", "--workspace", "--", "-D", "warnings"])
                && run("cargo", &["test", "--workspace"])
        }
        other => {
            if !other.is_empty() {
                eprintln!("xtask: unknown task {other:?}\n");
            }
            eprintln!("usage: cargo xtask <task>\n  test   run the workspace test suite\n  check  type-check the workspace\n  ci     fmt --check, clippy -D warnings, then test");
            exit(2);
        }
    };
    if !ok {
        exit(1);
    }
}

/// Run a command inherited stdio, returning whether it succeeded.
fn run(program: &str, args: &[&str]) -> bool {
    eprintln!("$ {program} {}", args.join(" "));
    Command::new(program)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
