// Licensed under the Apache-2.0 license.

//! Measures the peak runtime stack usage of each Runtime Command.
//!
//! This walks every command dispatched by `handle_command()` and, for each,
//! drives it with a simple representative parameter set while the emulator
//! tracks the lowest stack pointer reached. Peak usage is the distance from the
//! top of the runtime stack down to that high-water mark, i.e. the absolute
//! deepest the stack gets while servicing the command (including the dispatch
//! frames already on the stack).
//!
//! Commands are issued in an order that respects state dependencies: state
//! builders (auth manifest, exported CDI, tagged contexts) run before their
//! consumers, and the side-effecting `DISABLE_ATTESTATION` / `SHUTDOWN` run
//! last.
//!
//! The ML-DSA-87 commands are measured via `run_pqc_command_suite` (`SET_PQ_SEED`, `GET_PQ_CSR`,
//! `CERTIFY_KEY_EXTENDED_MLDSA87`, `MLDSA87_SIGNATURE_VERIFY`, `GET_PQ_CERT`,
//! `POPULATE_PQ_CERT`). The order matters: `SET_PQ_SEED` provisions the PQ.DevID
//! CDI and enables PQC mode, so running `GET_PQ_CSR` / `CERTIFY_KEY_EXTENDED_MLDSA87`
//! afterwards exercises their full ML-DSA-87 keygen+sign paths (the maximal stack
//! consumers) rather than early-returning.
//!
//! The mechanism relies on the emulator's stack-pointer tracking, so this test
//! only runs against the software emulator (not verilator/FPGA).
#![cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "sw_emu_stack_check_disable"
)))]

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_measurements_common::{
    measure_mldsa_dpe_subcommands, run_command_suite, run_pqc_command_suite, CommandSampler,
};
use caliptra_api::SocManager;
use caliptra_common::memory_layout::{STACK_ORG, STACK_SIZE};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::RtBootStatus;

/// Top of the runtime stack. The stack grows downward from here, so peak usage
/// is `STACK_TOP - min_sp`.
const STACK_TOP: u32 = STACK_ORG + STACK_SIZE;

fn peak_stack_usage(model: &DefaultHwModel) -> Option<u32> {
    model.stack_min_sp().map(|min_sp| STACK_TOP - min_sp)
}

struct StackSampler;

impl CommandSampler for StackSampler {
    fn before(&mut self, model: &mut DefaultHwModel) {
        model.reset_stack_high_water();
    }

    fn after(&mut self, model: &mut DefaultHwModel) -> u64 {
        let peak = peak_stack_usage(model)
            .expect("no stack activity observed; was the model built with stack_info?");
        // When CALIPTRA_EMU_STACK_WATERMARK_LOG is set, append this command's
        // high-water `(pc, sp)` events so they can be symbolized against the
        // firmware ELF. Each block is labeled by peak so commands are distinguishable.
        if let Some(path) = std::env::var_os("CALIPTRA_EMU_STACK_WATERMARK_LOG") {
            use std::io::Write;
            let events = model.take_stack_watermark_events();
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .expect("open stack watermark log");
            writeln!(f, "# peak_bytes={} events={}", peak, events.len()).unwrap();
            for (pc, sp) in events {
                writeln!(f, "{pc:#010x} {sp:#010x}").unwrap();
            }
        }
        // When CALIPTRA_EMU_STACK_SP_TRACE is set, append this command's full
        // stack-pointer-change trace (allocs and frees). A post-processor replays
        // it to reconstruct the live call stack and read off any sub-chain (e.g.
        // ML-DSA sign) frame-by-frame, independent of the global peak path.
        if let Some(path) = std::env::var_os("CALIPTRA_EMU_STACK_SP_TRACE") {
            use std::io::Write;
            let events = model.take_stack_sp_events();
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .expect("open stack sp trace");
            writeln!(f, "# peak_bytes={} sp_events={}", peak, events.len()).unwrap();
            for (pc, sp) in events {
                writeln!(f, "{pc:#010x} {sp:#010x}").unwrap();
            }
        }
        peak as u64
    }
}

#[test]
fn measure_runtime_command_stack_usage() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut results: Vec<(&'static str, u32)> = Vec::new();

    // Measure the PQC commands first so GET_PQ_CSR / CERTIFY_KEY_EXTENDED_MLDSA87
    // run with PQC mode enabled and before the side-effecting suite tail.
    results.extend(
        run_pqc_command_suite(&mut model, &mut StackSampler)
            .into_iter()
            .map(|(name, v)| (name, v as u32)),
    );

    results.extend(
        run_command_suite(&mut model, &mut StackSampler)
            .into_iter()
            .map(|(name, v)| (name, v as u32)),
    );

    // The ML-DSA INVOKE_DPE subcommands are measured against their own dedicated
    // model (see measure_mldsa_dpe_subcommands): the full set can't be sequenced in
    // this shared model (default-context retirement + DISABLE_ATTESTATION conflicts).
    results.extend(
        measure_mldsa_dpe_subcommands(&mut StackSampler)
            .into_iter()
            .map(|(name, v)| (name, v as u32)),
    );

    // Report, highest stack usage first. Size the name column to the widest
    // command name (some INVOKE_DPE_MLDSA87(..) subcommands are >40 chars) so the
    // bytes/% columns stay aligned instead of being pushed out by long names.
    results.sort_by_key(|b| std::cmp::Reverse(b.1));
    let name_w = results
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or(0)
        .max("command".len());
    println!("\nRuntime command peak stack usage (runtime stack = {STACK_SIZE} bytes):");
    println!("{:<name_w$} {:>10} {:>8}", "command", "bytes", "% stack");
    println!("{}", "-".repeat(name_w + 20));
    for (name, bytes) in &results {
        let pct = (*bytes as f64) * 100.0 / (STACK_SIZE as f64);
        println!("{name:<name_w$} {bytes:>10} {pct:>7.1}%");
    }

    // Sanity: every command must consume some stack and stay within the budget.
    for (name, bytes) in &results {
        assert!(*bytes > 0, "{name} reported zero stack usage");
        assert!(
            *bytes < STACK_SIZE,
            "{name} stack usage {bytes} exceeds runtime stack size {STACK_SIZE}"
        );
    }
}

/// Stack depth reached inside `DpeCrypto::derive_key_pair_mldsa` (and the ML-DSA
/// keygen/sign/verify primitives), per command.
///
/// Where `measure_runtime_command_stack_usage` reports each command's global
/// peak, this reports how deep the stack already is when a given function runs —
/// i.e. the budget available to work nested at that point, such as a pair-wise
/// consistency check added to ML-DSA key derivation.
///
/// It reuses the emulator SP trace: every SP change is recorded with the `pc`
/// that made it, so the deepest SP recorded while `pc` is inside a function's
/// address range is that function's own frame bottom. Callees are excluded (their
/// `pc` is outside the range), so this is the depth *at* the function, not the
/// depth of everything it calls. Subtracting that depth from the command peak
/// gives what the function's subtree costs when it is the peak path.
///
/// Requires `CALIPTRA_EMU_STACK_SP_TRACE=1` (gates SP-trace recording when the
/// model is built) and `--test-threads=1` (the trace is process-global and
/// memory-hungry).
#[test]
#[ignore]
fn measure_derive_key_pair_mldsa_depth() {
    use std::cell::RefCell;
    use std::rc::Rc;

    assert!(
        std::env::var_os("CALIPTRA_EMU_STACK_SP_TRACE").is_some(),
        "set CALIPTRA_EMU_STACK_SP_TRACE=1 to enable SP-trace recording"
    );

    // Functions of interest, as (label, mangled-name substring). Ordered roughly
    // outermost-first so the report reads as a call chain.
    const TARGETS: &[(&str, &str)] = &[
        ("DpeCrypto::derive_key_pair_mldsa", "derive_key_pair_mldsa"),
        ("DpeCrypto Signer::sign", "Signer$GT$4sign"),
        ("DpeCrypto Signer::public_key", "Signer$GT$10public_key"),
        ("DpeCrypto::sign_helper_mldsa", "sign_helper_mldsa"),
        ("DpeCrypto::pwct_mldsa", "pwct_mldsa"),
        ("Mldsa87Kat::execute", "Mldsa87Kat7execute"),
        ("Mldsa87Kat::kat_keygen", "kat_keygen"),
        ("Mldsa87Kat::kat_sign_and_verify", "kat_sign_and_verify"),
        ("Mldsa87Kat::kat_verify", "10kat_verify"),
        ("Mldsa87::pub_from_seed", "pub_from_seed"),
        ("Mldsa87::verify", "Mldsa876verify"),
        ("Mldsa87::verify_mu", "Mldsa879verify_mu"),
        ("Mldsa87::verify_response_buffer", "verify_response_buffer"),
        ("mldsa87::generate_key_internal", "generate_key_internal"),
        ("mldsa87::sign_internal_with_mu", "sign_internal_with_mu"),
    ];

    let elf = caliptra_builder::build_firmware_elf(&caliptra_builder::firmware::APP_WITH_UART)
        .expect("build runtime elf");
    let syms = caliptra_builder::elf_symbols(&elf).expect("parse elf symbols");
    // Per target, the set of [lo, hi) code ranges its symbols occupy.
    let ranges: Vec<Vec<(u32, u32)>> = TARGETS
        .iter()
        .map(|(label, needle)| {
            let r: Vec<(u32, u32)> = syms
                .iter()
                // Skip closures: identical ones (e.g. the SHAKE-absorb callbacks in
                // the sign and verify response-buffer paths) get folded onto one
                // address, so a closure hit does not prove its parent ran.
                .filter(|s| s.name.contains(needle) && s.size > 0 && !s.name.contains("closure"))
                .map(|s| (s.value as u32, (s.value + s.size) as u32))
                .collect();
            if r.is_empty() {
                println!("{label}: no symbol matched (inlined or absent)");
            }
            for (lo, hi) in &r {
                println!("{label}: [{lo:#010x}, {hi:#010x}) size={}", hi - lo);
            }
            r
        })
        .collect();

    // Rows are appended in command order by the sampler and zipped with the
    // (name, _) results the suites return in that same order.
    type Row = (u32, Vec<u32>);
    let rows: Rc<RefCell<Vec<Row>>> = Rc::new(RefCell::new(Vec::new()));

    struct FnDepthSampler {
        ranges: Vec<Vec<(u32, u32)>>,
        rows: Rc<RefCell<Vec<Row>>>,
    }
    impl CommandSampler for FnDepthSampler {
        fn before(&mut self, model: &mut DefaultHwModel) {
            model.reset_stack_high_water();
        }
        fn after(&mut self, model: &mut DefaultHwModel) -> u64 {
            let peak = peak_stack_usage(model).unwrap_or(0);
            let events = model.take_stack_sp_events();
            let depths: Vec<u32> = self
                .ranges
                .iter()
                .map(|target| {
                    events
                        .iter()
                        .filter(|(pc, _)| target.iter().any(|(lo, hi)| pc >= lo && pc < hi))
                        .map(|(_, sp)| STACK_TOP - *sp)
                        .max()
                        .unwrap_or(0)
                })
                .collect();
            let primary = u64::from(depths[0]);
            self.rows.borrow_mut().push((peak, depths));
            primary
        }
    }

    let mut sampler = FnDepthSampler {
        ranges,
        rows: rows.clone(),
    };

    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut names: Vec<&'static str> = Vec::new();
    names.extend(
        run_pqc_command_suite(&mut model, &mut sampler)
            .into_iter()
            .map(|(n, _)| n),
    );
    names.extend(
        run_command_suite(&mut model, &mut sampler)
            .into_iter()
            .map(|(n, _)| n),
    );
    names.extend(
        measure_mldsa_dpe_subcommands(&mut sampler)
            .into_iter()
            .map(|(n, _)| n),
    );

    let rows = rows.borrow();
    assert_eq!(
        names.len(),
        rows.len(),
        "sampler rows out of sync with names"
    );
    let mut table: Vec<(&str, u32, Vec<u32>)> = names
        .iter()
        .zip(rows.iter())
        .filter(|(_, (_, d))| d.iter().any(|v| *v > 0))
        .map(|(n, (peak, d))| (*n, *peak, d.clone()))
        .collect();
    table.sort_by_key(|r| std::cmp::Reverse(r.2[0]));

    let label_w = TARGETS.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    println!("\nStack depth at ML-DSA functions (runtime stack = {STACK_SIZE} bytes)");
    println!(
        "depth = that function's own frame bottom; free = stack - depth.\n\
         A function listed under a command was reached by it; omitted = not reached.\n"
    );
    for (name, peak, depths) in &table {
        println!("{name}  (command peak {peak}, free {})", STACK_SIZE - peak);
        for ((label, _), d) in TARGETS.iter().zip(depths.iter()) {
            if *d > 0 {
                println!(
                    "    {label:<label_w$}  depth {d:>6}   free {:>6}",
                    STACK_SIZE - d
                );
            }
        }
        println!();
    }
    assert!(!table.is_empty(), "no command reached any ML-DSA function");
}
