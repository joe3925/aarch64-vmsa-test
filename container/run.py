#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time

import build
import prepare

OUTPUT = Path("/output")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "target",
        choices=["ns-el2", "secure-el2", "realm-el2", "realm-stage2", "root-el3"],
    )
    parser.add_argument("--filter")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare-only", action="store_true")
    mode.add_argument("--require-cache", action="store_true")
    return parser.parse_args()


def fvp_command(images: build.FirmwareImages, target: str) -> list[str]:
    command = [
        "FVP_Base_RevC-2xAEMvA",
        "-C", f"bp.secureflashloader.fname={images.bl1}",
        "-C", f"bp.flashloader0.fname={images.fip}",
        "-C", "bp.refcounter.non_arch_start_at_default=1",
        "-C", "bp.vis.disable_visualisation=1",
        "-C", "bp.pl011_uart0.out_file=-",
        "-C", "bp.pl011_uart0.unbuffered_output=1",
        "-C", "bp.pl011_uart1.out_file=-",
        "-C", "bp.pl011_uart1.unbuffered_output=1",
        "-C", "bp.pl011_uart2.out_file=-",
        "-C", "bp.pl011_uart2.unbuffered_output=1",
        "-C", "bp.pl011_uart3.out_file=-",
        "-C", "bp.pl011_uart3.unbuffered_output=1",
        "-C", "bp.terminal_0.start_telnet=0",
        "-C", "bp.terminal_1.start_telnet=0",
        "-C", "bp.terminal_2.start_telnet=0",
        "-C", "bp.terminal_3.start_telnet=0",
        "-C", "pctl.startup=0.0.0.0",
        # TF-A's warm-boot context code is built with FEAT_CSV2_2 support and
        # restores SCXTNUM_EL2 on every secondary PE.  Keep the model feature
        # contract identical for every profile that can issue CPU_ON, rather
        # than relying on a profile-specific launch to happen to enable it.
        "-C", "cluster0.restriction_on_speculative_execution=2",
        "-C", "cluster1.restriction_on_speculative_execution=2",
        "-C", "cluster0.restriction_on_speculative_execution_aarch32=2",
        "-C", "cluster1.restriction_on_speculative_execution_aarch32=2",
    ]
    if target == "secure-el2":
        command.extend(["-C", "bp.secure_memory=1"])
    if target == "secure-el2":
        command.extend([
            "-C", "cluster0.has_secure_el2=1",
            "-C", "cluster1.has_secure_el2=1",
            "-C", "cci550.addr_width=48",
            "-C", "cluster0.PA_SIZE=52",
            "-C", "cluster1.PA_SIZE=52",
            "-C", "cluster0.has_arm_v8-5=1",
            "-C", "cluster1.has_arm_v8-5=1",
            "-C", "cluster0.has_large_va=1",
            "-C", "cluster1.has_large_va=1",
            "-C", "cluster0.has_52bit_address_with_4k=2",
            "-C", "cluster1.has_52bit_address_with_4k=2",
            "-C", "cluster0.has_52bit_address_with_16k=2",
            "-C", "cluster1.has_52bit_address_with_16k=2",
            "-C", "cluster0.has_16k_granule=1",
            "-C", "cluster1.has_16k_granule=1",
            "-C", "cluster0.has_arm_v9-4=1",
            "-C", "cluster1.has_arm_v9-4=1",
            "-C", "cluster0.has_128_bit_tt_descriptors=2",
            "-C", "cluster1.has_128_bit_tt_descriptors=2",
            "-C", "cluster0.bti_support_level=1",
            "-C", "cluster1.bti_support_level=1",
            "-C", "cluster0.memory_tagging_support_level=2",
            "-C", "cluster1.memory_tagging_support_level=2",
        ])
    if target == "ns-el2":
        command.extend([
            "-C", "cci550.addr_width=48",
            "-C", "cluster0.PA_SIZE=52",
            "-C", "cluster1.PA_SIZE=52",
            "-C", "cluster0.has_arm_v8-7=1",
            "-C", "cluster1.has_arm_v8-7=1",
            "-C", "cluster0.has_large_va=1",
            "-C", "cluster1.has_large_va=1",
            "-C", "cluster0.has_52bit_address_with_4k=2",
            "-C", "cluster1.has_52bit_address_with_4k=2",
            "-C", "cluster0.has_52bit_address_with_16k=2",
            "-C", "cluster1.has_52bit_address_with_16k=2",
            "-C", "cluster0.has_16k_granule=1",
            "-C", "cluster1.has_16k_granule=1",
            "-C", "cluster0.has_arm_v9-4=1",
            "-C", "cluster1.has_arm_v9-4=1",
            "-C", "cluster0.has_128_bit_tt_descriptors=2",
            "-C", "cluster1.has_128_bit_tt_descriptors=2",
        ])
    if target == "root-el3":
        command.extend([
            "-C", "bp.has_rme=1",
            "-C", "bp.secure_memory=0",
            "-C", "cci550.addr_width=48",
            "-C", "cluster0.PA_SIZE=52",
            "-C", "cluster1.PA_SIZE=52",
            "-C", "cluster0.has_large_va=1",
            "-C", "cluster1.has_large_va=1",
            "-C", "cluster0.has_52bit_address_with_4k=2",
            "-C", "cluster1.has_52bit_address_with_4k=2",
            "-C", "cluster0.has_52bit_address_with_16k=2",
            "-C", "cluster1.has_52bit_address_with_16k=2",
            "-C", "cluster0.has_16k_granule=1",
            "-C", "cluster1.has_16k_granule=1",
            "-C", "cluster0.rme_support_level=2",
            "-C", "cluster1.rme_support_level=2",
            "-C", "cluster0.gicv3.cpuintf-mmap-access-level=2",
            "-C", "cluster1.gicv3.cpuintf-mmap-access-level=2",
            "-C", "cluster0.gicv3.without-DS-support=1",
            "-C", "cluster1.gicv3.without-DS-support=1",
            "-C", "cluster0.gicv4.mask-virtual-interrupt=1",
            "-C", "cluster1.gicv4.mask-virtual-interrupt=1",
            "-C", "cluster0.has_arm_v9-4=1",
            "-C", "cluster1.has_arm_v9-4=1",
            "-C", "cluster0.has_128_bit_tt_descriptors=2",
            "-C", "cluster1.has_128_bit_tt_descriptors=2",
        ])
    if target in {"realm-el2", "realm-stage2"}:
        command.extend([
            "-C", "bp.has_rme=1",
            "-C", "bp.secure_memory=0",
            "-C", "cci550.addr_width=48",
            "-C", "cluster0.PA_SIZE=52",
            "-C", "cluster1.PA_SIZE=52",
            "-C", "cluster0.rme_support_level=2",
            "-C", "cluster1.rme_support_level=2",
            "-C", "cluster0.has_large_va=1",
            "-C", "cluster1.has_large_va=1",
            "-C", "cluster0.has_52bit_address_with_4k=2",
            "-C", "cluster1.has_52bit_address_with_4k=2",
            "-C", "cluster0.has_52bit_address_with_16k=2",
            "-C", "cluster1.has_52bit_address_with_16k=2",
            "-C", "cluster0.has_16k_granule=1",
            "-C", "cluster1.has_16k_granule=1",
            "-C", "cluster0.has_arm_v9-4=1",
            "-C", "cluster1.has_arm_v9-4=1",
            "-C", "cluster0.has_128_bit_tt_descriptors=2",
            "-C", "cluster1.has_128_bit_tt_descriptors=2",
            "-C", "cluster0.gicv3.cpuintf-mmap-access-level=2",
            "-C", "cluster1.gicv3.cpuintf-mmap-access-level=2",
            "-C", "cluster0.gicv3.without-DS-support=1",
            "-C", "cluster1.gicv3.without-DS-support=1",
            "-C", "cluster0.gicv4.mask-virtual-interrupt=1",
            "-C", "cluster1.gicv4.mask-virtual-interrupt=1",
        ])
    if target == "realm-stage2":
        command.extend([
            "-C", "cluster0.has_16k_granule=1",
            "-C", "cluster1.has_16k_granule=1",
            "-C", "cluster0.has_arm_v8-1=1",
            "-C", "cluster1.has_arm_v8-1=1",
            "-C", "cluster0.has_large_system_ext=1",
            "-C", "cluster1.has_large_system_ext=1",
            "-C", "cluster0.has_arm_v8-2=1",
            "-C", "cluster1.has_arm_v8-2=1",
            "-C", "cluster0.has_large_va=1",
            "-C", "cluster1.has_large_va=1",
            "-C", "cluster0.has_sve=1",
            "-C", "cluster1.has_sve=1",
            "-C", "cluster0.has_arm_v8-3=1",
            "-C", "cluster1.has_arm_v8-3=1",
            "-C", "cluster0.has_arm_v8-4=1",
            "-C", "cluster1.has_arm_v8-4=1",
            "-C", "cluster0.has_amu=1",
            "-C", "cluster1.has_amu=1",
            "-C", "cluster0.has_arm_v8-5=1",
            "-C", "cluster1.has_arm_v8-5=1",
            "-C", "cluster0.has_branch_target_exception=1",
            "-C", "cluster1.has_branch_target_exception=1",
            "-C", "cluster0.has_rndr=1",
            "-C", "cluster1.has_rndr=1",
            "-C", "cluster0.has_arm_v8-6=1",
            "-C", "cluster1.has_arm_v8-6=1",
            "-C", "cluster0.ecv_support_level=2",
            "-C", "cluster1.ecv_support_level=2",
            "-C", "cluster0.enhanced_pac2_level=3",
            "-C", "cluster1.enhanced_pac2_level=3",
            "-C", "cluster0.has_arm_v8-7=1",
            "-C", "cluster1.has_arm_v8-7=1",
            "-C", "cluster0.has_arm_v9-0=1",
            "-C", "cluster1.has_arm_v9-0=1",
            "-C", "cluster0.max_32bit_el=0",
            "-C", "cluster1.max_32bit_el=0",
            "-C", "cluster0.sve.has_sve2=1",
            "-C", "cluster1.sve.has_sve2=1",
            "-C", "cluster0.has_arm_v9-1=1",
            "-C", "cluster1.has_arm_v9-1=1",
            "-C", "cluster0.has_arm_v9-2=1",
            "-C", "cluster1.has_arm_v9-2=1",
            "-C", "cluster0.has_brbe=1",
            "-C", "cluster1.has_brbe=1",
            "-C", "cluster0.sve.has_sme=1",
            "-C", "cluster1.sve.has_sme=1",
        ])
    return command


def copy_stream(stream, destination: Path, messages: queue.Queue[tuple[str, str]]) -> None:
    with destination.open("w", encoding="utf-8", errors="replace") as log:
        for line in iter(stream.readline, ""):
            log.write(line)
            log.flush()
            messages.put((destination.name, line))
    stream.close()


def run_fvp(images: build.FirmwareImages, target: str) -> None:
    command = fvp_command(images, target)
    print("VMSA-INFRA FVP_START", flush=True)
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise RuntimeError("failed to capture FVP output")
    messages: queue.Queue[tuple[str, str]] = queue.Queue()
    stdout_thread = threading.Thread(
        target=copy_stream,
        args=(process.stdout, OUTPUT / "uart.log", messages),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=copy_stream,
        args=(process.stderr, OUTPUT / "fvp.stderr.log", messages),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    saw_end = False
    shutdown_deadline: float | None = None
    while stdout_thread.is_alive() or stderr_thread.is_alive() or not messages.empty():
        if shutdown_deadline is not None and time.monotonic() >= shutdown_deadline:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            shutdown_deadline = None
        try:
            source, line = messages.get(timeout=0.25)
        except queue.Empty:
            if process.poll() is not None and not stdout_thread.is_alive() and not stderr_thread.is_alive():
                break
            continue
        if source == "uart.log" and line.startswith(("@@VMSA ", "VMSA-INFRA ")):
            sys.stdout.write(line)
            sys.stdout.flush()
        if source == "uart.log" and line.startswith("@@VMSA END ") and not saw_end:
            saw_end = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            shutdown_deadline = time.monotonic() + 1
    if saw_end:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)
    else:
        status = process.wait()
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)
        raise RuntimeError(f"FVP exited with status {status} before END")


def main() -> int:
    arguments = parse_arguments()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "firmware.log").write_bytes(b"")
    repositories: dict[str, Path] = {}
    try:
        images = build.restore_cached_build(arguments.target)
        if images is None and arguments.require_cache:
            raise RuntimeError("required firmware cache entry is missing or invalid")
        if images is None:
            print("VMSA-INFRA PHASE prepare-start", flush=True)
            repositories = prepare.prepare(arguments.target)
            print("VMSA-INFRA PHASE prepare-complete", flush=True)
            print("VMSA-INFRA PHASE build-start", flush=True)
            images = build.build(arguments.target, repositories)
            print("VMSA-INFRA PHASE build-complete", flush=True)
            prepare.cleanup(repositories)
            repositories = {}
            print("VMSA-INFRA PHASE package-complete", flush=True)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"build/packaging failure: {error}", file=sys.stderr, flush=True)
        result = 20
    else:
        if arguments.prepare_only:
            result = 0
        else:
            try:
                run_images = build.materialize_run_images(images, arguments.filter)
                run_fvp(run_images, arguments.target)
            except (OSError, RuntimeError) as error:
                print(f"FVP startup/runtime failure: {error}", file=sys.stderr, flush=True)
                result = 21
            else:
                result = 0
    finally:
        try:
            prepare.cleanup(repositories)
        except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
            print(f"worktree cleanup failure: {error}", file=sys.stderr, flush=True)
            result = 20
    return result


if __name__ == "__main__":
    raise SystemExit(main())
