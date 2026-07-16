#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, "/tools/Base_RevC_AEMvA_pkg/Iris/Python")
from iris.debug.Model import NewNetworkModel


def main() -> int:
    test_name = os.environ.get("VMSA_IRIS_TEST", "formats.d128-stage1-active")
    target = os.environ.get("VMSA_IRIS_TARGET", "ns-el2")
    physical_memory_space = {
        "secure-el2": "Physical Memory (Secure)",
        "realm-el2": "Physical Memory (Realm)",
        "realm-stage2": "Physical Memory (Realm)",
        "root-el3": "Physical Memory (Root)",
    }.get(target, "Physical Memory (Non Secure)")
    command = [
        "FVP_Base_RevC-2xAEMvA",
        "-I",
        "--iris-port",
        "7100",
        "-Q",
        "1",
        "-C",
        "bp.secureflashloader.fname=/debug/bl1.bin",
        "-C",
        "bp.flashloader0.fname=/debug/fip.bin",
        "-C",
        "bp.refcounter.non_arch_start_at_default=1",
        "-C",
        "bp.vis.disable_visualisation=1",
        "-C",
        "bp.pl011_uart0.out_file=-",
        "-C",
        "bp.pl011_uart0.unbuffered_output=1",
        "-C",
        "bp.pl011_uart1.out_file=-",
        "-C",
        "bp.pl011_uart1.unbuffered_output=1",
        "-C",
        "bp.pl011_uart2.out_file=-",
        "-C",
        "bp.pl011_uart2.unbuffered_output=1",
        "-C",
        "bp.pl011_uart3.out_file=-",
        "-C",
        "bp.pl011_uart3.unbuffered_output=1",
        "-C",
        "bp.terminal_0.start_telnet=0",
        "-C",
        "bp.terminal_1.start_telnet=0",
        "-C",
        "pctl.startup=0.0.0.0",
        "-C",
        "cci550.addr_width=48",
        "-C",
        "cluster0.PA_SIZE=52",
        "-C",
        "cluster1.PA_SIZE=52",
        "-C",
        f"cluster0.has_arm_v8-{'5' if target == 'secure-el2' else '7'}=1",
        "-C",
        f"cluster1.has_arm_v8-{'5' if target == 'secure-el2' else '7'}=1",
        "-C",
        "cluster0.has_large_va=1",
        "-C",
        "cluster1.has_large_va=1",
        "-C",
        "cluster0.has_52bit_address_with_4k=2",
        "-C",
        "cluster1.has_52bit_address_with_4k=2",
        "-C",
        "cluster0.has_52bit_address_with_16k=2",
        "-C",
        "cluster1.has_52bit_address_with_16k=2",
        "-C",
        "cluster0.has_16k_granule=1",
        "-C",
        "cluster1.has_16k_granule=1",
        "-C",
        "cluster0.has_arm_v9-4=1",
        "-C",
        "cluster1.has_arm_v9-4=1",
        "-C",
        "cluster0.has_128_bit_tt_descriptors=2",
        "-C",
        "cluster1.has_128_bit_tt_descriptors=2",
    ]
    if target == "secure-el2":
        command.extend(
            [
                "-C",
                "bp.secure_memory=1",
                "-C",
                "cluster0.has_secure_el2=1",
                "-C",
                "cluster1.has_secure_el2=1",
                "-C",
                "cluster0.bti_support_level=1",
                "-C",
                "cluster1.bti_support_level=1",
                "-C",
                "cluster0.memory_tagging_support_level=2",
                "-C",
                "cluster1.memory_tagging_support_level=2",
            ]
        )
    if target == "root-el3":
        command.extend(
            [
                "-C",
                "bp.has_rme=1",
                "-C",
                "bp.secure_memory=0",
                "-C",
                "cluster0.rme_support_level=2",
                "-C",
                "cluster1.rme_support_level=2",
                "-C",
                "cluster0.gicv3.cpuintf-mmap-access-level=2",
                "-C",
                "cluster1.gicv3.cpuintf-mmap-access-level=2",
                "-C",
                "cluster0.gicv3.without-DS-support=1",
                "-C",
                "cluster1.gicv3.without-DS-support=1",
                "-C",
                "cluster0.gicv4.mask-virtual-interrupt=1",
                "-C",
                "cluster1.gicv4.mask-virtual-interrupt=1",
                "-C",
                "cluster0.restriction_on_speculative_execution=2",
                "-C",
                "cluster1.restriction_on_speculative_execution=2",
                "-C",
                "cluster0.restriction_on_speculative_execution_aarch32=2",
                "-C",
                "cluster1.restriction_on_speculative_execution_aarch32=2",
            ]
        )
    if target in {"realm-el2", "realm-stage2"}:
        command.extend(
            [
                "-C",
                "bp.has_rme=1",
                "-C",
                "bp.secure_memory=0",
                "-C",
                "cluster0.rme_support_level=2",
                "-C",
                "cluster1.rme_support_level=2",
                "-C",
                "cluster0.gicv3.cpuintf-mmap-access-level=2",
                "-C",
                "cluster1.gicv3.cpuintf-mmap-access-level=2",
                "-C",
                "cluster0.gicv3.without-DS-support=1",
                "-C",
                "cluster1.gicv3.without-DS-support=1",
                "-C",
                "cluster0.gicv4.mask-virtual-interrupt=1",
                "-C",
                "cluster1.gicv4.mask-virtual-interrupt=1",
                "-C",
                "cluster0.restriction_on_speculative_execution=2",
                "-C",
                "cluster1.restriction_on_speculative_execution=2",
                "-C",
                "cluster0.restriction_on_speculative_execution_aarch32=2",
                "-C",
                "cluster1.restriction_on_speculative_execution_aarch32=2",
            ]
        )
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    reached_test = threading.Event()
    model_holder = []

    def copy_output() -> None:
        assert process.stdout is not None
        with open("/debug/iris-uart.log", "w", encoding="utf-8") as log:
            for line in process.stdout:
                log.write(line)
                log.flush()
                if line.startswith(f"@@VMSA RUN {test_name}"):
                    if model_holder:
                        try:
                            model_holder[0].stop(timeout=5)
                        finally:
                            reached_test.set()

    thread = threading.Thread(target=copy_output, daemon=True)
    thread.start()
    model = None
    try:
        deadline = time.monotonic() + 20
        while model is None and time.monotonic() < deadline:
            try:
                model = NewNetworkModel(port=7100, timeoutInMs=10000)
            except Exception:
                time.sleep(0.1)
        if model is None:
            raise RuntimeError("Iris server did not become ready")
        model_holder.append(model)
        cpu = model.get_cpus()[0]
        model.run(blocking=False)
        if not reached_test.wait(20):
            raise RuntimeError(f"guest did not reach {test_name}")
        breakpoint_address = os.environ.get("VMSA_IRIS_BREAKPOINT")
        breakpoint_register = os.environ.get("VMSA_IRIS_REGISTER_BREAKPOINT")
        if breakpoint_address is not None or breakpoint_register is not None:
            breakpoint = (
                cpu.add_bpt_prog(int(breakpoint_address, 0))
                if breakpoint_address is not None
                else cpu.add_bpt_reg(breakpoint_register, on_read=False, on_write=True)
            )
            hits = model.run(blocking=True, timeout=5)
            print(
                "breakpoint-hit="
                + str(any(hit.number == breakpoint.number for hit in hits))
            )
            if os.environ.get("VMSA_IRIS_STEPS") is not None:
                breakpoint.delete()
                cpu.client.irisCall().step_syncStep(
                    instId=cpu.instId,
                    steps=int(os.environ["VMSA_IRIS_STEPS"], 0),
                    unit="instruction",
                )
        else:
            model.run(blocking=False)
            time.sleep(float(os.environ.get("VMSA_IRIS_DELAY", "1")))
            if model.is_running:
                model.stop(timeout=5)
        print(f"cpu={cpu.instName}")
        print("memory-spaces=" + ",".join(cpu.memory_spaces_by_name.keys()))
        for register in [
            "PC",
            "PSTATE",
            "SP",
            "SP_EL1",
            "SP_EL2",
            "ESR_EL1",
            "FAR_EL1",
            "ELR_EL1",
            "SPSR_EL1",
            "ESR_EL2",
            "FAR_EL2",
            "HPFAR_EL2",
            "ELR_EL2",
            "SPSR_EL2",
            "ESR_EL3",
            "FAR_EL3",
            "ELR_EL3",
            "SPSR_EL3",
            "SCTLR_EL2",
            "SCTLR_EL1",
            "HCR_EL2",
            "VTCR_EL2",
            "VTTBR_EL2",
            "VSTCR_EL2",
            "VSTTBR_EL2",
            "SCR_EL3",
            "TCR_EL2",
            "TCR_EL1",
            "TCR_EL3",
            "TCR2_EL2",
            "TCR2_EL1",
            "TTBR0_EL2",
            "TTBR0_EL1",
            "TTBR0_EL3",
            "MAIR_EL2",
            "MAIR_EL1",
            "MAIR_EL3",
            "PIR_EL1",
            "PIRE0_EL1",
            "PIR_EL2",
            "PIRE0_EL2",
            "HCRX_EL2",
            "PAR_EL1",
            "VBAR_EL1",
            "VBAR_EL2",
            "VBAR_EL3",
        ]:
            try:
                print(f"{register}=0x{cpu.read_register(register):016x}")
            except Exception as error:
                print(f"{register}=unavailable:{error}")
        if cpu.read_register("HCR_EL2") & 1:
            table = cpu.read_register("VTTBR_EL2") & 0x0000_FFFF_FFFF_F000
            address = cpu.read_register("FAR_EL2")
            for level, shift in enumerate((39, 30, 21, 12)):
                index = (address >> shift) & 0x1FF
                raw = int.from_bytes(
                    cpu.read_memory(
                        table + index * 8,
                        memory_space=physical_memory_space,
                        size=8,
                    ),
                    "little",
                )
                print(f"stage2-fault-l{level}=0x{raw:016x}")
                if raw & 0b11 != 0b11:
                    break
                table = raw & 0x0000_FFFF_FFFF_F000
        if cpu.read_register("TCR2_EL2") & (1 << 5):
            root = cpu.read_register("TTBR0_EL2") & 0x00FF_FFFF_FFFF_FFE0
            addresses = {
                "pc": cpu.read_register("PC"),
                "stack": cpu.read_register("SP"),
                "fault": cpu.read_register("FAR_EL2"),
                "vector": cpu.read_register("VBAR_EL2"),
            }
            input_bits = 64 - (cpu.read_register("TCR_EL2") & 0x3F)
            levels = (input_bits - 12 + 7) // 8
            start_level = 4 - levels
            for name, address in addresses.items():
                table = root
                levels_and_shifts = [
                    (level, 12 + 8 * (3 - level))
                    for level in range(start_level, 4)
                ]
                for level, shift in levels_and_shifts:
                    index = (address >> shift) & 0xFF
                    descriptor_address = table + index * 16
                    low = int.from_bytes(
                        cpu.read_memory(
                            descriptor_address,
                            memory_space=physical_memory_space,
                            size=8,
                        ),
                        "little",
                    )
                    high = int.from_bytes(
                        cpu.read_memory(
                            descriptor_address + 8,
                            memory_space=physical_memory_space,
                            size=8,
                        ),
                        "little",
                    )
                    raw = low | high << 64
                    print(f"{name}-l{level}=0x{raw:032x}")
                    table = raw & 0x00FF_FFFF_FFFF_F000
        else:
            current_el = "EL3" if target == "root-el3" else "EL2"
            tcr = cpu.read_register(f"TCR_{current_el}")
            tg0 = (tcr >> 14) & 0x3
            if tg0 == 0b00:
                granule_shift, index_bits, all_shifts = 12, 9, (39, 30, 21, 12)
            elif tg0 == 0b10:
                granule_shift, index_bits, all_shifts = 14, 11, (47, 36, 25, 14)
            elif tg0 == 0b01:
                granule_shift, index_bits, all_shifts = 16, 13, (42, 29, 16)
            else:
                raise RuntimeError(f"reserved TG0 encoding {tg0}")
            root = cpu.read_register(f"TTBR0_{current_el}") & ~((1 << granule_shift) - 1)
            input_bits = 64 - (tcr & 0x3F)
            ds = tcr & (1 << (32 if current_el == "EL3" else 59))
            if granule_shift == 12 and ds:
                all_shifts = (48, 39, 30, 21, 12)
            shifts = tuple(shift for shift in all_shifts if shift < input_bits)
            first_level = len(all_shifts) - len(shifts)
            addresses = {
                "entry": cpu.read_register(f"ELR_{current_el}"),
                "stack": cpu.read_register("SP"),
                "fault": cpu.read_register(f"FAR_{current_el}"),
                "vector": cpu.read_register(f"VBAR_{current_el}"),
            }
            if os.environ.get("VMSA_IRIS_ADDRESS") is not None:
                addresses["requested"] = int(os.environ["VMSA_IRIS_ADDRESS"], 0)
            for name, address in addresses.items():
                table = root
                for level, shift in enumerate(shifts, start=first_level):
                    index = (address >> shift) & ((1 << index_bits) - 1)
                    raw = int.from_bytes(
                        cpu.read_memory(
                            table + index * 8,
                            memory_space=physical_memory_space,
                            size=8,
                        ),
                        "little",
                    )
                    print(f"{name}-l{level}=0x{raw:016x}")
                    table = raw & ~((1 << granule_shift) - 1)
                    if raw & 0b11 != 0b11:
                        break
        return 0
    finally:
        if model is not None:
            try:
                model.release(shutdown=True)
            except Exception:
                pass
        try:
            os.killpg(process.pid, 15)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, 9)
            except ProcessLookupError:
                pass
            process.wait()
        thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
