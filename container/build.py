#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from pathlib import Path
import os
import re
import shutil
import subprocess
import urllib.request

import prepare

TESTS = Path("/workspace/tests")
OUTPUT = Path("/output")
SOURCE_TARGET_WORKSPACE = TESTS / "target"
TARGET_WORKSPACE = OUTPUT / "target-workspace"
CRATE_UNDER_TEST = Path("/workspace/aarch64-vmsa")
TARGET_TRIPLE = "aarch64-unknown-none-softfloat"
RUST_TOOLCHAIN = "nightly-2026-04-07"
RUSTUP_VERSION = "1.28.2"
RUSTUP_SHA256_X86_64 = "20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c"
RUSTUP_SHA256_AARCH64 = "e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c"
FIRMWARE_CACHE = Path("/cache/firmware-artifacts")
RUN_SELECTOR_MAGIC = b"VMSA-RUN-SELECTOR::V1::AARCH64!!"
RUN_SELECTOR_TRAILER = b"VMSA-RUN-SELECTOR::END::AARCH64!"
RUN_SELECTOR_ABI_VERSION = 1
RUN_SELECTOR_CAPACITY = 4096
RUN_SELECTOR_HEADER_BYTES = 48
ROOT_PAYLOAD_SOURCE_VIRTUAL = 0x7400_0000
ROOT_PAYLOAD_SOURCE_PHYSICAL = 0x8800_0000
ROOT_PAYLOAD_SOURCE_BYTES = 0x0020_0000
ROOT_PAYLOAD_CODE_VIRTUAL = 0xFFE0_0000
ROOT_PAYLOAD_CODE_PHYSICAL = ROOT_PAYLOAD_SOURCE_PHYSICAL
ROOT_PAYLOAD_CODE_BYTES = 0x0010_0000
ROOT_PAYLOAD_DATA_VIRTUAL = 0xFFDC_0000
ROOT_PAYLOAD_DATA_PHYSICAL = ROOT_PAYLOAD_SOURCE_PHYSICAL + ROOT_PAYLOAD_CODE_BYTES
ROOT_PAYLOAD_DATA_BYTES = 0x0004_0000
ROOT_PAYLOAD_DATA_LIMIT_VIRTUAL = ROOT_PAYLOAD_DATA_VIRTUAL + ROOT_PAYLOAD_DATA_BYTES


@dataclass(frozen=True)
class FirmwareImages:
    bl1: Path
    fip: Path


@dataclass(frozen=True)
class HafniumImage:
    binary: Path
    load_base: int
    memory_bytes: int


def _hash_tree(digest: "hashlib._Hash", root: Path, excluded: set[str]) -> None:
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in excluded for part in relative.parts) or not path.is_file():
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)


def firmware_cache_key(target: str) -> str:
    digest = hashlib.sha256()
    digest.update(target.encode("utf-8"))
    digest.update(b"\0")
    for revision in (
        prepare.TF_A_REVISION,
        prepare.TF_A_TESTS_REVISION,
        prepare.HAFNIUM_REVISION,
        prepare.TF_RMM_REVISION,
        RUST_TOOLCHAIN,
        TARGET_TRIPLE,
    ):
        digest.update(revision.encode("ascii"))
        digest.update(b"\0")
    _hash_tree(digest, SOURCE_TARGET_WORKSPACE, {"target", "external"})
    _hash_tree(digest, TESTS / "integration", {".git", "__pycache__"})
    _hash_tree(digest, CRATE_UNDER_TEST, {".git", "target", "__pycache__"})
    for source in (TESTS / "container" / "build.py", TESTS / "container" / "prepare.py"):
        digest.update(source.name.encode("ascii"))
        digest.update(source.read_bytes())
    return digest.hexdigest()


def restore_cached_build(target: str) -> FirmwareImages | None:
    key = firmware_cache_key(target)
    cached = FIRMWARE_CACHE / f"{target}-{key}"
    bl1 = cached / "bl1.bin"
    fip = cached / "fip.bin"
    if not bl1.is_file() or not fip.is_file() or bl1.stat().st_size == 0 or fip.stat().st_size == 0:
        return None
    try:
        validate_runtime_selector(fip)
    except RuntimeError:
        shutil.rmtree(cached)
        return None
    artifacts = OUTPUT / "artifacts"
    shutil.copytree(cached, artifacts, dirs_exist_ok=True)
    os.utime(cached)
    print(f"VMSA-INFRA PHASE firmware-cache-hit key={key[:16]}", flush=True)
    return FirmwareImages(artifacts / "bl1.bin", artifacts / "fip.bin")


def cache_build(target: str, images: FirmwareImages) -> None:
    key = firmware_cache_key(target)
    FIRMWARE_CACHE.mkdir(parents=True, exist_ok=True)
    destination = FIRMWARE_CACHE / f"{target}-{key}"
    temporary = FIRMWARE_CACHE / f".{target}-{key}-{os.getpid()}"
    if temporary.exists():
        shutil.rmtree(temporary)
    shutil.copytree(OUTPUT / "artifacts", temporary)
    if destination.exists():
        shutil.rmtree(temporary)
    else:
        temporary.rename(destination)
    entries = sorted(
        FIRMWARE_CACHE.glob(f"{target}-*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for stale in entries[8:]:
        shutil.rmtree(stale)
    require_file(images.bl1)
    require_file(images.fip)


def prepare_target_workspace() -> None:
    if TARGET_WORKSPACE.exists():
        shutil.rmtree(TARGET_WORKSPACE)

    def ignore(path: str, names: list[str]) -> set[str]:
        relative = Path(path).relative_to(SOURCE_TARGET_WORKSPACE)
        ignored = {"target"} if not relative.parts else set()
        if relative == Path("external"):
            ignored.add("aarch64-vmsa")
        return ignored.intersection(names)

    shutil.copytree(SOURCE_TARGET_WORKSPACE, TARGET_WORKSPACE, ignore=ignore)
    external = TARGET_WORKSPACE / "external"
    external.mkdir(parents=True, exist_ok=True)
    (external / "aarch64-vmsa").symlink_to(CRATE_UNDER_TEST, target_is_directory=True)


def checked(command: list[str], cwd: Path, log: Path, environment: dict[str, str] | None = None) -> None:
    with log.open("ab") as output:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if process.stdout is None:
            process.kill()
            process.wait()
            raise RuntimeError(f"failed to capture output for {command[0]}")
        for chunk in iter(process.stdout.readline, b""):
            output.write(chunk)
            output.flush()
        status = process.wait()
    if status != 0:
        raise subprocess.CalledProcessError(status, command)


def rust_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["CARGO_HOME"] = "/cache/cargo"
    environment["RUSTUP_HOME"] = "/cache/rustup"
    environment["PATH"] = f"/cache/cargo/bin:{environment.get('PATH', '')}"
    return environment


def ensure_rust(log: Path) -> None:
    machine = os.uname().machine
    if machine == "x86_64":
        triple = "x86_64-unknown-linux-gnu"
        expected = RUSTUP_SHA256_X86_64
    elif machine in {"aarch64", "arm64"}:
        triple = "aarch64-unknown-linux-gnu"
        expected = RUSTUP_SHA256_AARCH64
    else:
        raise RuntimeError(f"unsupported container architecture {machine}")
    cargo = Path("/cache/cargo/bin/cargo")
    rustup = Path("/cache/cargo/bin/rustup")
    environment = rust_environment()
    if not rustup.is_file():
        installer = Path("/cache/rustup-init")
        url = f"https://static.rust-lang.org/rustup/archive/{RUSTUP_VERSION}/{triple}/rustup-init"
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise RuntimeError(f"rustup-init checksum mismatch: expected {expected}, got {actual}")
        installer.write_bytes(data)
        installer.chmod(0o755)
        checked(
            [str(installer), "-y", "--no-modify-path", "--profile", "minimal", "--default-toolchain", "none"],
            TESTS,
            log,
            environment,
        )
    checked(
        [
            str(rustup), "toolchain", "install", RUST_TOOLCHAIN,
            "--profile", "minimal", "--target", TARGET_TRIPLE,
            "--component", "rust-src",
        ],
        TESTS,
        log,
        environment,
    )
    if not cargo.is_file():
        raise RuntimeError("pinned Rust installation did not provide cargo")


def build_rust(package: str, log: Path) -> Path:
    checked(
        [
            "/cache/cargo/bin/cargo", f"+{RUST_TOOLCHAIN}", "build",
            "-Z", "build-std=core", "--release", "--locked", "-p", package,
        ],
        TARGET_WORKSPACE,
        log,
        rust_environment(),
    )
    archive = TARGET_WORKSPACE / "target" / TARGET_TRIPLE / "release" / f"lib{package.replace('-', '_')}.a"
    if not archive.is_file():
        raise RuntimeError(f"Rust build did not produce {archive}")
    artifacts = OUTPUT / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    shutil.copy2(archive, artifacts / archive.name)
    return archive


def write_filter_header(worktree: Path) -> None:
    header = worktree / "vmsa_filter.h"
    header.write_text(
        "#ifndef VMSA_FILTER_H\n"
        "#define VMSA_FILTER_H\n"
        "#include <stddef.h>\n"
        "#include <stdint.h>\n"
        f"#define VMSA_RUN_SELECTOR_ABI_VERSION UINT32_C({RUN_SELECTOR_ABI_VERSION})\n"
        f"#define VMSA_RUN_SELECTOR_CAPACITY UINT32_C({RUN_SELECTOR_CAPACITY})\n"
        "typedef struct vmsa_run_selector {\n"
        "\tuint8_t magic[32];\n"
        "\tuint32_t abi_version;\n"
        "\tuint32_t capacity;\n"
        "\tuint32_t filter_bytes;\n"
        "\tuint32_t reserved;\n"
        "\tuint8_t filter[VMSA_RUN_SELECTOR_CAPACITY];\n"
        "\tuint8_t trailer[32];\n"
        "} vmsa_run_selector_t;\n"
        "_Static_assert(offsetof(vmsa_run_selector_t, filter_bytes) == 40U, \"selector length offset\");\n"
        "_Static_assert(offsetof(vmsa_run_selector_t, filter) == 48U, \"selector filter offset\");\n"
        "_Static_assert(offsetof(vmsa_run_selector_t, trailer) == 48U + VMSA_RUN_SELECTOR_CAPACITY, \"selector trailer offset\");\n"
        "static const vmsa_run_selector_t vmsa_run_selector\n"
        "\t__attribute__((used, aligned(16), section(\".rodata.vmsa_run_selector\"))) = {\n"
        f"\t.magic = \"{RUN_SELECTOR_MAGIC.decode('ascii')}\",\n"
        "\t.abi_version = VMSA_RUN_SELECTOR_ABI_VERSION,\n"
        "\t.capacity = VMSA_RUN_SELECTOR_CAPACITY,\n"
        "\t.filter_bytes = 0U,\n"
        "\t.reserved = 0U,\n"
        "\t.filter = { 0U },\n"
        f"\t.trailer = \"{RUN_SELECTOR_TRAILER.decode('ascii')}\",\n"
        "};\n"
        "static inline const uint8_t *vmsa_filter_data(void)\n"
        "{\n"
        "\treturn vmsa_run_selector.filter;\n"
        "}\n"
        "static inline size_t vmsa_filter_length(void)\n"
        "{\n"
        "\tconst volatile vmsa_run_selector_t *selector = &vmsa_run_selector;\n"
        "\tuint32_t bytes = selector->filter_bytes;\n"
        "\tif (selector->abi_version != VMSA_RUN_SELECTOR_ABI_VERSION ||\n"
        "\t    selector->capacity != VMSA_RUN_SELECTOR_CAPACITY ||\n"
        "\t    selector->reserved != 0U || bytes > VMSA_RUN_SELECTOR_CAPACITY) {\n"
        "\t\treturn 0U;\n"
        "\t}\n"
        "\treturn (size_t)bytes;\n"
        "}\n"
        "#define VMSA_FILTER (vmsa_filter_data())\n"
        "#define VMSA_FILTER_LENGTH (vmsa_filter_length())\n"
        "#endif\n",
        encoding="utf-8",
    )


def materialize_run_images(images: FirmwareImages, filter_value: str | None) -> FirmwareImages:
    run_artifacts = OUTPUT / "run-artifacts"
    if run_artifacts.exists():
        shutil.rmtree(run_artifacts)
    run_artifacts.mkdir(parents=True)
    bl1 = run_artifacts / "bl1.bin"
    fip = run_artifacts / "fip.bin"
    shutil.copy2(images.bl1, bl1)
    shutil.copy2(images.fip, fip)
    patch_runtime_filter(fip, filter_value)
    return FirmwareImages(bl1, fip)


def patch_runtime_filter(fip: Path, filter_value: str | None) -> None:
    encoded = (filter_value or "").encode("utf-8")
    if len(encoded) > RUN_SELECTOR_CAPACITY:
        raise RuntimeError(
            f"test filter is {len(encoded)} bytes; maximum is {RUN_SELECTOR_CAPACITY}"
        )
    image = bytearray(fip.read_bytes())
    marker = validate_runtime_selector_image(image)
    header_end = marker + RUN_SELECTOR_HEADER_BYTES
    filter_end = header_end + RUN_SELECTOR_CAPACITY
    struct.pack_into("<I", image, marker + 40, len(encoded))
    image[header_end:filter_end] = b"\0" * RUN_SELECTOR_CAPACITY
    image[header_end:header_end + len(encoded)] = encoded
    fip.write_bytes(image)
    print(
        f"VMSA-INFRA PHASE runtime-selector filter-bytes={len(encoded)}",
        flush=True,
    )


def validate_runtime_selector(fip: Path) -> None:
    validate_runtime_selector_image(fip.read_bytes())


def validate_runtime_selector_image(image: bytes | bytearray) -> int:
    marker = image.find(RUN_SELECTOR_MAGIC)
    if marker < 0:
        raise RuntimeError("firmware does not contain the runtime test selector")
    if image.find(RUN_SELECTOR_MAGIC, marker + 1) >= 0:
        raise RuntimeError("firmware contains more than one runtime test selector")
    header_end = marker + RUN_SELECTOR_HEADER_BYTES
    filter_end = header_end + RUN_SELECTOR_CAPACITY
    trailer_end = filter_end + len(RUN_SELECTOR_TRAILER)
    if trailer_end > len(image):
        raise RuntimeError("runtime test selector is truncated")
    abi_version, capacity, _, reserved = struct.unpack_from("<IIII", image, marker + 32)
    if abi_version != RUN_SELECTOR_ABI_VERSION or capacity != RUN_SELECTOR_CAPACITY or reserved != 0:
        raise RuntimeError(
            "runtime test selector ABI mismatch: "
            f"version={abi_version} capacity={capacity} reserved={reserved}"
        )
    if bytes(image[filter_end:trailer_end]) != RUN_SELECTOR_TRAILER:
        raise RuntimeError("runtime test selector trailer mismatch")
    return marker


def write_root_payload_header(worktree: Path) -> None:
    header = worktree / "vmsa_root_payload.h"
    header.write_text(
        "#ifndef VMSA_ROOT_PAYLOAD_H\n"
        "#define VMSA_ROOT_PAYLOAD_H\n"
        "#include <stdint.h>\n"
        f"#define VMSA_ROOT_PAYLOAD_ENTRY UINT64_C(0x{ROOT_PAYLOAD_CODE_VIRTUAL:x})\n"
        f"#define VMSA_ROOT_PAYLOAD_SOURCE_VIRTUAL UINT64_C(0x{ROOT_PAYLOAD_SOURCE_VIRTUAL:x})\n"
        f"#define VMSA_ROOT_PAYLOAD_SOURCE_PHYSICAL UINT64_C(0x{ROOT_PAYLOAD_SOURCE_PHYSICAL:x})\n"
        f"#define VMSA_ROOT_PAYLOAD_SOURCE_BYTES UINT64_C(0x{ROOT_PAYLOAD_SOURCE_BYTES:x})\n"
        f"#define VMSA_ROOT_PAYLOAD_CODE_VIRTUAL UINT64_C(0x{ROOT_PAYLOAD_CODE_VIRTUAL:x})\n"
        f"#define VMSA_ROOT_PAYLOAD_CODE_SOURCE_VIRTUAL UINT64_C(0x{ROOT_PAYLOAD_SOURCE_VIRTUAL:x})\n"
        f"#define VMSA_ROOT_PAYLOAD_CODE_BYTES UINT64_C(0x{ROOT_PAYLOAD_CODE_BYTES:x})\n"
        f"#define VMSA_ROOT_PAYLOAD_DATA_VIRTUAL UINT64_C(0x{ROOT_PAYLOAD_DATA_VIRTUAL:x})\n"
        f"#define VMSA_ROOT_PAYLOAD_DATA_SOURCE_VIRTUAL UINT64_C(0x{ROOT_PAYLOAD_SOURCE_VIRTUAL + ROOT_PAYLOAD_CODE_BYTES:x})\n"
        f"#define VMSA_ROOT_PAYLOAD_DATA_BYTES UINT64_C(0x{ROOT_PAYLOAD_DATA_BYTES:x})\n"
        "#endif\n",
        encoding="utf-8",
    )


def build_root_payload(payload: Path, log: Path) -> tuple[Path, Path]:
    build_directory = OUTPUT / "root-payload"
    if build_directory.exists():
        shutil.rmtree(build_directory)
    build_directory.mkdir(parents=True)

    entry = build_directory / "entry.S"
    entry.write_text(
        ".section .text.vmsa_root_payload_entry,\"ax\",%progbits\n"
        ".balign 16\n"
        ".global vmsa_root_payload_entry\n"
        ".type vmsa_root_payload_entry, %function\n"
        "vmsa_root_payload_entry:\n"
        "\tb vmsa_test_root_el3_entry\n"
        ".size vmsa_root_payload_entry, . - vmsa_root_payload_entry\n",
        encoding="utf-8",
    )
    runtime = build_directory / "runtime.c"
    runtime.write_text(
        "#include <stddef.h>\n"
        "#include <stdint.h>\n"
        "void *memcpy(void *destination, const void *source, size_t bytes)\n"
        "{\n"
        "\tuint8_t *out = destination;\n"
        "\tconst uint8_t *in = source;\n"
        "\tfor (size_t index = 0; index < bytes; ++index) out[index] = in[index];\n"
        "\treturn destination;\n"
        "}\n"
        "void *memmove(void *destination, const void *source, size_t bytes)\n"
        "{\n"
        "\tuint8_t *out = destination;\n"
        "\tconst uint8_t *in = source;\n"
        "\tif (out <= in) {\n"
        "\t\tfor (size_t index = 0; index < bytes; ++index) out[index] = in[index];\n"
        "\t} else {\n"
        "\t\tfor (size_t index = bytes; index != 0; --index) out[index - 1] = in[index - 1];\n"
        "\t}\n"
        "\treturn destination;\n"
        "}\n"
        "void *memset(void *destination, int value, size_t bytes)\n"
        "{\n"
        "\tuint8_t *out = destination;\n"
        "\tfor (size_t index = 0; index < bytes; ++index) out[index] = (uint8_t)value;\n"
        "\treturn destination;\n"
        "}\n"
        "int memcmp(const void *left, const void *right, size_t bytes)\n"
        "{\n"
        "\tconst uint8_t *a = left;\n"
        "\tconst uint8_t *b = right;\n"
        "\tfor (size_t index = 0; index < bytes; ++index) {\n"
        "\t\tif (a[index] != b[index]) return a[index] < b[index] ? -1 : 1;\n"
        "\t}\n"
        "\treturn 0;\n"
        "}\n"
        "int bcmp(const void *left, const void *right, size_t bytes)\n"
        "{\n"
        "\treturn memcmp(left, right, bytes);\n"
        "}\n"
        "size_t strlen(const char *value)\n"
        "{\n"
        "\tsize_t bytes = 0;\n"
        "\twhile (value[bytes] != '\\0') ++bytes;\n"
        "\treturn bytes;\n"
        "}\n"
        "__attribute__((noreturn)) void abort(void)\n"
        "{\n"
        "\tfor (;;) __asm__ volatile (\"wfe\");\n"
        "}\n"
        "__attribute__((noreturn)) void __stack_chk_fail(void)\n"
        "{\n"
        "\tabort();\n"
        "}\n",
        encoding="utf-8",
    )
    linker = build_directory / "root-payload.ld"
    linker.write_text(
        "OUTPUT_FORMAT(\"elf64-littleaarch64\")\n"
        "OUTPUT_ARCH(aarch64)\n"
        "ENTRY(vmsa_root_payload_entry)\n"
        "PHDRS\n"
        "{\n"
        "\tdata PT_LOAD FLAGS(6);\n"
        "\tcode PT_LOAD FLAGS(5);\n"
        "}\n"
        "SECTIONS\n"
        "{\n"
        f"\t. = 0x{ROOT_PAYLOAD_DATA_VIRTUAL:x};\n"
        f"\t.data : AT(0x{ROOT_PAYLOAD_DATA_PHYSICAL:x})\n"
        "\t{\n"
        "\t\t*(.data .data.* .sdata .sdata.* .data.rel.ro .data.rel.ro.*)\n"
        "\t\t*(.tdata .tdata.* .got .got.* .got.plt)\n"
        "\t\t*(.preinit_array .preinit_array.* .init_array .init_array.*)\n"
        "\t\t*(.fini_array .fini_array.* .ctors .ctors.* .dtors .dtors.* .jcr)\n"
        "\t} :data\n"
        f"\t.bss (NOLOAD) : AT(0x{ROOT_PAYLOAD_DATA_PHYSICAL:x} + (ADDR(.bss) - 0x{ROOT_PAYLOAD_DATA_VIRTUAL:x}))\n"
        "\t{\n"
        "\t\t*(.bss .bss.* .sbss .sbss.* .tbss .tbss.*)\n"
        "\t\t*(COMMON)\n"
        "\t} :data\n"
        "\t. = ALIGN(0x1000);\n"
        f"\tASSERT(. <= 0x{ROOT_PAYLOAD_DATA_LIMIT_VIRTUAL:x}, \"Root payload data exceeds its 256 KiB Root slot\")\n"
        f"\t. = 0x{ROOT_PAYLOAD_CODE_VIRTUAL:x};\n"
        f"\t.text : AT(0x{ROOT_PAYLOAD_CODE_PHYSICAL:x})\n"
        "\t{\n"
        "\t\tKEEP(*(.text.vmsa_root_payload_entry))\n"
        "\t\t*(.text .text.* .init .fini .plt .iplt)\n"
        "\t} :code\n"
        f"\t.rodata : AT(0x{ROOT_PAYLOAD_CODE_PHYSICAL:x} + (ADDR(.rodata) - 0x{ROOT_PAYLOAD_CODE_VIRTUAL:x}))\n"
        "\t{\n"
        "\t\t*(.rodata .rodata.* .srodata .srodata.*)\n"
        "\t\t*(.eh_frame_hdr .eh_frame .eh_frame.*)\n"
        "\t\t*(.gcc_except_table .gcc_except_table.*)\n"
        "\t} :code\n"
        f"\tASSERT(. <= 0x{ROOT_PAYLOAD_CODE_VIRTUAL + ROOT_PAYLOAD_CODE_BYTES:x}, \"Root payload code exceeds its 1 MiB Root slot\")\n"
        "\t/DISCARD/ : { *(.comment) *(.note*) *(.debug*) *(.ARM.attributes) *(.llvm_addrsig) }\n"
        "}\n",
        encoding="utf-8",
    )

    entry_object = build_directory / "entry.o"
    runtime_object = build_directory / "runtime.o"
    checked(
        [
            "aarch64-none-elf-gcc", "-c", "-ffreestanding", "-fno-stack-protector",
            "-o", str(entry_object), str(entry),
        ],
        build_directory,
        log,
    )
    checked(
        [
            "aarch64-none-elf-gcc", "-c", "-Os", "-ffreestanding", "-fno-builtin",
            "-fno-stack-protector", "-fdata-sections", "-ffunction-sections",
            "-o", str(runtime_object), str(runtime),
        ],
        build_directory,
        log,
    )
    elf = build_directory / "root-payload.elf"
    map_file = build_directory / "root-payload.map"
    checked(
        [
            "aarch64-none-elf-gcc", "-nostdlib", "-static",
            "-Wl,--gc-sections", "-Wl,--no-undefined", "-Wl,--fatal-warnings",
            "-Wl,--build-id=none", f"-Wl,-T,{linker}", f"-Wl,-Map,{map_file}",
            "-o", str(elf), str(entry_object), str(runtime_object),
            "-Wl,--start-group", str(payload), "-lgcc", "-Wl,--end-group",
        ],
        build_directory,
        log,
    )
    load_base, image, file_backed_bytes = elf_load_image(elf, "Root payload")
    if load_base != ROOT_PAYLOAD_CODE_PHYSICAL:
        raise RuntimeError(
            "Root payload ELF load base is incorrect: "
            f"expected=0x{ROOT_PAYLOAD_CODE_PHYSICAL:x} actual=0x{load_base:x}"
        )
    if len(image) > ROOT_PAYLOAD_SOURCE_BYTES:
        raise RuntimeError(
            "Root payload ELF exceeds its reserved BL33 image: "
            f"bytes={len(image)} limit={ROOT_PAYLOAD_SOURCE_BYTES}"
        )
    binary = build_directory / "root-payload.bin"
    binary.write_bytes(image.ljust(ROOT_PAYLOAD_SOURCE_BYTES, b"\0"))

    bridge_source = build_directory / "bridge.c"
    bridge_source.write_text(
        "const unsigned char vmsa_root_bridge_marker = 0U;\n",
        encoding="utf-8",
    )
    bridge_object = build_directory / "bridge.o"
    checked(
        [
            "aarch64-none-elf-gcc", "-c", "-Os", "-ffreestanding",
            "-fno-stack-protector", "-fdata-sections",
            "-o", str(bridge_object), str(bridge_source),
        ],
        build_directory,
        log,
    )
    bridge = build_directory / "libvmsa_root_bridge.a"
    checked(
        ["aarch64-none-elf-ar", "rcs", str(bridge), str(bridge_object)],
        build_directory,
        log,
    )

    artifacts = OUTPUT / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    for source in (elf, map_file, binary):
        shutil.copy2(source, artifacts / source.name)
    print(
        "VMSA-INFRA PHASE root-payload-extent "
        f"load-base=0x{load_base:x} file-backed-bytes={file_backed_bytes} "
        f"memory-bytes={len(image)}",
        flush=True,
    )
    return binary, bridge


def build_tftf(
    worktree: Path,
    test_archive: Path | None,
    log: Path,
    test_suite: str | None = None,
    build_realm_payload: bool = False,
    realm_payload_archive: Path | None = None,
) -> Path:
    write_filter_header(worktree)
    command = [
        "make", "-j", str(os.cpu_count() or 1), "PLAT=fvp", "DEBUG=1",
        "CROSS_COMPILE=aarch64-none-elf-",
        f"TESTS={test_suite or ('vmsa' if test_archive else 'psci')}",
    ]
    if test_archive:
        command.append(f"VMSA_TEST_LIB={test_archive}")
    if build_realm_payload:
        command.append("ENABLE_REALM_PAYLOAD_TESTS=1")
    if realm_payload_archive:
        command.append(f"VMSA_REALM_LIB={realm_payload_archive}")
    checked(command, worktree, log)
    image = worktree / "build" / "fvp" / "debug" / "tftf.bin"
    require_file(image)
    artifacts = OUTPUT / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    for name in ("tftf.elf", "tftf.map"):
        source = image.parent / "tftf" / name
        if source.is_file():
            shutil.copy2(source, artifacts / name)
    return image


def build_tf_a(
    worktree: Path,
    log: Path,
    extra: list[str],
    *,
    debug: bool = True,
) -> FirmwareImages:
    build_name = "debug" if debug else "release"
    command = [
        "make", "-j", str(os.cpu_count() or 1), "PLAT=fvp",
        f"DEBUG={int(debug)}",
        "CROSS_COMPILE=aarch64-none-elf-", "ENABLE_ASSERTIONS=1", *extra, "all", "fip",
    ]
    checked(command, worktree, log)
    directory = worktree / "build" / "fvp" / build_name
    images = FirmwareImages(directory / "bl1.bin", directory / "fip.bin")
    require_file(images.bl1)
    require_file(images.fip)
    return images


def build_ns_el2(repositories: dict[str, Path], log: Path) -> FirmwareImages:
    emit_build_step(1, 4, "rust-payload")
    payload = build_rust("vmsa-test-ns-el2", log)
    emit_build_step(2, 4, "tf-a-tests")
    tftf = build_tftf(repositories["tf-a-tests"], payload, log)
    emit_build_step(3, 4, "tf-a-firmware")
    images = build_tf_a(
        repositories["tf-a"],
        log,
        [
            "ARM_ARCH_MAJOR=9",
            "ARM_ARCH_MINOR=4",
            "ENABLE_FEAT_D128=2",
            "ENABLE_FEAT_AIE=1",
            "CTX_INCLUDE_AARCH32_REGS=0",
            f"BL33={tftf}",
        ],
    )
    emit_build_step(4, 4, "package-cache")
    return images


def build_root_el3(repositories: dict[str, Path], log: Path) -> FirmwareImages:
    emit_build_step(1, 4, "rust-payload")
    payload_archive = build_rust("vmsa-test-root-el3", log)
    emit_build_step(2, 4, "root-bridge")
    payload, bridge = build_root_payload(payload_archive, log)
    write_filter_header(repositories["tf-a"])
    write_root_payload_header(repositories["tf-a"])
    # The complete Root catalog is too large for RME's SRAM-resident BL31.
    # Keep only the EL3 bridge in BL31 and load the Rust image through BL33's
    # normal DRAM image slot; the bridge maps and invokes it while still at EL3.
    emit_build_step(3, 4, "tf-a-firmware")
    images = build_tf_a(
        repositories["tf-a"], log,
        [
            "CTX_INCLUDE_AARCH32_REGS=0",
            "FVP_TRUSTED_SRAM_SIZE=512",
            "ENABLE_RME=1",
            "ARM_ARCH_MAJOR=9",
            "ARM_ARCH_MINOR=4",
            "ENABLE_FEAT_D128=2",
            "ENABLE_FEAT_AIE=1",
            f"BL33={payload}",
            f"VMSA_ROOT_LIB={bridge}",
            f"VMSA_TEST_INCLUDE={repositories['tf-a']}",
        ],
    )
    emit_build_step(4, 4, "package-cache")
    return images


def build_realm_el2(repositories: dict[str, Path], log: Path) -> FirmwareImages:
    emit_build_step(1, 4, "rust-payload")
    payload = build_rust("vmsa-test-realm-el2", log)
    emit_build_step(2, 4, "tf-a-tests")
    tftf = build_tftf(repositories["tf-a-tests"], None, log)
    write_filter_header(repositories["tf-a"])
    emit_build_step(3, 4, "tf-a-firmware")
    images = build_tf_a(
        repositories["tf-a"], log,
        [
            "ENABLE_RME=1",
            "ARM_ARCH_MAJOR=9",
            "ARM_ARCH_MINOR=4",
            "ENABLE_FEAT_D128=2",
            "ENABLE_FEAT_AIE=1",
            "CTX_INCLUDE_AARCH32_REGS=0",
            f"BL33={tftf}",
            f"VMSA_REALM_LIB={payload}",
            f"VMSA_TEST_INCLUDE={repositories['tf-a']}",
        ],
    )
    emit_build_step(4, 4, "package-cache")
    return images


def elf_load_image(elf: Path, image_name: str) -> tuple[int, bytes, int]:
    source = elf.read_bytes()
    if len(source) < 64 or source[:4] != b"\x7fELF":
        raise RuntimeError(f"{image_name} output is not an ELF64 image: {elf}")
    if source[4] != 2 or source[5] != 1:
        raise RuntimeError(f"{image_name} ELF must be little-endian ELF64: {elf}")

    program_offset = struct.unpack_from("<Q", source, 32)[0]
    program_entry_bytes = struct.unpack_from("<H", source, 54)[0]
    program_entries = struct.unpack_from("<H", source, 56)[0]
    if program_entry_bytes < 56:
        raise RuntimeError(f"{image_name} ELF has an invalid program-header size: {elf}")

    segments: list[tuple[int, int, int, int]] = []
    load_base: int | None = None
    memory_end = 0
    for index in range(program_entries):
        header_offset = program_offset + index * program_entry_bytes
        if header_offset + 56 > len(source):
            raise RuntimeError(f"{image_name} ELF has a truncated program-header table: {elf}")
        p_type, _, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", source, header_offset
        )
        if p_type != 1 or p_memsz == 0:
            continue
        if p_filesz > p_memsz:
            raise RuntimeError(
                f"{image_name} ELF PT_LOAD has file bytes beyond its memory extent: "
                f"index={index} filesz={p_filesz} memsz={p_memsz}"
            )
        if p_offset + p_filesz > len(source):
            raise RuntimeError(
                f"{image_name} ELF PT_LOAD file range is truncated: "
                f"index={index} offset={p_offset} filesz={p_filesz} "
                f"elf-bytes={len(source)}"
            )
        address = p_paddr or p_vaddr
        segments.append((address, p_offset, p_filesz, p_memsz))
        load_base = address if load_base is None else min(load_base, address)
        memory_end = max(memory_end, address + p_memsz)

    if load_base is None or memory_end <= load_base:
        raise RuntimeError(f"{image_name} ELF has no loadable memory extent: {elf}")

    output = bytearray(memory_end - load_base)
    occupied = bytearray(len(output))
    file_backed_bytes = 0
    for index, (address, p_offset, p_filesz, _) in enumerate(segments):
        destination = address - load_base
        destination_end = destination + p_filesz
        segment = source[p_offset:p_offset + p_filesz]
        for byte_index, value in enumerate(segment):
            output_index = destination + byte_index
            if occupied[output_index] and output[output_index] != value:
                raise RuntimeError(
                    f"{image_name} ELF has conflicting overlapping PT_LOAD file ranges: "
                    f"segment={index} image-offset={output_index}"
                )
            if not occupied[output_index]:
                file_backed_bytes += 1
                occupied[output_index] = 1
            output[output_index] = value
        if destination_end > len(output):
            raise RuntimeError(
                f"{image_name} ELF PT_LOAD exceeds the computed memory image: "
                f"segment={index} end={destination_end} image={len(output)}"
            )

    return load_base, bytes(output), file_backed_bytes


def write_hafnium_memory_image(binary: Path, elf: Path) -> HafniumImage:
    load_base, image, file_backed_bytes = elf_load_image(elf, "Hafnium")
    binary.write_bytes(image)
    print(
        "VMSA-INFRA PHASE hafnium-image-extent "
        f"load-base=0x{load_base:x} file-backed-bytes={file_backed_bytes} "
        f"memory-bytes={len(image)}",
        flush=True,
    )
    return HafniumImage(binary, load_base, len(image))


def build_hafnium(worktree: Path, payload: Path, log: Path) -> HafniumImage:
    command = [
        "make", "-j", str(os.cpu_count() or 1), "PROJECT=reference",
        "PLATFORM=secure_aem_v8a_fvp_vhe",
        f"GN_ARGS_EXTRA=vmsa_test_lib=\"{payload}\"",
    ]
    checked(command, worktree, log)
    elf_candidates = list((worktree / "out" / "reference").rglob("hafnium.elf"))
    if len(elf_candidates) != 1:
        raise RuntimeError(f"expected one Hafnium ELF, found {elf_candidates}")
    artifacts = OUTPUT / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    elf = artifacts / "secure-el2-hafnium.elf"
    binary = artifacts / "secure-el2-hafnium.bin"
    shutil.copy2(elf_candidates[0], elf)
    return write_hafnium_memory_image(binary, elf)


def configure_fvp_spmc_manifest(tf_a: Path, hafnium: HafniumImage) -> None:
    manifest = tf_a / "plat/arm/board/fvp/fdts/fvp_spmc_manifest.dts"
    source = manifest.read_text(encoding="utf-8")
    attribute_start = source.find("\tattribute {")
    if attribute_start < 0:
        raise RuntimeError(f"FVP SPMC manifest has no attribute node: {manifest}")
    attribute_end = source.find("\n\t};", attribute_start)
    if attribute_end < 0:
        raise RuntimeError(f"FVP SPMC manifest attribute node is unterminated: {manifest}")
    attribute_end += len("\n\t};")
    attribute = source[attribute_start:attribute_end]

    load = re.search(
        r"(?m)^(?P<indent>[ \t]*)load_address[ \t]*=[ \t]*<0x0[ \t]+(?P<value>0x[0-9a-fA-F]+)>;[ \t]*$",
        attribute,
    )
    size = re.search(
        r"(?m)^(?P<indent>[ \t]*)binary_size[ \t]*=[ \t]*<(?P<value>0x[0-9a-fA-F]+)>;[ \t]*$",
        attribute,
    )
    if load is None or size is None:
        raise RuntimeError(
            f"FVP SPMC manifest attribute node lacks load_address or binary_size: {manifest}"
        )
    manifest_base = int(load.group("value"), 16)
    if manifest_base != hafnium.load_base:
        raise RuntimeError(
            "Hafnium ELF load base does not match the FVP SPMC manifest: "
            f"elf=0x{hafnium.load_base:x} manifest=0x{manifest_base:x}"
        )
    if hafnium.memory_bytes <= 0 or hafnium.memory_bytes > 0xFFFF_FFFF:
        raise RuntimeError(
            f"Hafnium memory extent cannot be represented in the SPMC manifest: {hafnium.memory_bytes}"
        )

    replacement = (
        f'{size.group("indent")}binary_size = <0x{hafnium.memory_bytes:x}>;'
    )
    updated_attribute = (
        attribute[:size.start()] + replacement + attribute[size.end():]
    )
    manifest.write_text(
        source[:attribute_start] + updated_attribute + source[attribute_end:],
        encoding="utf-8",
    )
    print(
        "VMSA-INFRA PHASE spmc-manifest-extent "
        f"load-base=0x{hafnium.load_base:x} binary-size=0x{hafnium.memory_bytes:x}",
        flush=True,
    )


def stage_secure_partitions(tf_a_tests: Path, tftf: Path) -> Path:
    staging = OUTPUT / "secure-partitions"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    layout = TESTS / "integration" / "hafnium" / "files" / "sp_layout.json"
    shutil.copy2(layout, staging / layout.name)
    build_directory = tftf.parent
    for name in ["cactus.bin", "ivy.bin"]:
        source = build_directory / name
        require_file(source)
        shutil.copy2(source, staging / name)
    manifests = tf_a_tests / "spm" / "cactus" / "plat" / "arm" / "fvp" / "fdts"
    for name in ["cactus.dts", "cactus-secondary.dts", "cactus-tertiary.dts"]:
        source = manifests / name
        require_file(source)
        shutil.copy2(source, staging / name)
    ivy = tf_a_tests / "spm" / "ivy" / "app" / "plat" / "arm" / "fvp" / "fdts" / "ivy-sel1.dts"
    require_file(ivy)
    shutil.copy2(ivy, staging / ivy.name)
    return staging / layout.name


def build_secure_el2(repositories: dict[str, Path], log: Path) -> FirmwareImages:
    emit_build_step(1, 5, "rust-payload")
    payload = build_rust("vmsa-test-secure-el2", log)
    write_filter_header(repositories["hafnium"])
    emit_build_step(2, 5, "hafnium")
    hafnium = build_hafnium(repositories["hafnium"], payload, log)
    configure_fvp_spmc_manifest(repositories["tf-a"], hafnium)
    emit_build_step(3, 5, "tf-a-tests")
    tftf = build_tftf(repositories["tf-a-tests"], None, log)
    layout = stage_secure_partitions(repositories["tf-a-tests"], tftf)
    emit_build_step(4, 5, "tf-a-firmware")
    images = build_tf_a(
        repositories["tf-a"], log,
        [
            "SPD=spmd",
            "SPMD_SPM_AT_SEL2=1",
            "ARM_ARCH_MAJOR=9",
            "ARM_ARCH_MINOR=4",
            "ENABLE_FEAT_D128=2",
            "ENABLE_FEAT_AIE=1",
            "CTX_INCLUDE_AARCH32_REGS=0",
            "BRANCH_PROTECTION=1",
            "CTX_INCLUDE_PAUTH_REGS=1",
            "ENABLE_FEAT_MTE2=1",
            f"BL32={hafnium.binary}",
            f"BL33={tftf}",
            f"SP_LAYOUT_FILE={layout}",
        ],
    )
    emit_build_step(5, 5, "package-cache")
    return images


def build_tf_rmm(worktree: Path, log: Path) -> Path:
    build = worktree / "build-vmsa"
    environment = os.environ.copy()
    environment["CROSS_COMPILE"] = "aarch64-none-elf-"
    checked([
        "cmake", "-G", "Ninja", "-S", str(worktree), "-B", str(build),
        "-DRMM_CONFIG=fvp_defcfg", "-DRMM_TOOLCHAIN=llvm", "-DCMAKE_BUILD_TYPE=Debug",
    ], worktree, log, environment)
    checked(["cmake", "--build", str(build)], worktree, log, environment)
    candidates = list(build.rglob("rmm.img"))
    if len(candidates) != 1:
        raise RuntimeError(f"expected one TF-RMM image, found {candidates}")
    return candidates[0]


def build_realm_stage2(repositories: dict[str, Path], log: Path) -> FirmwareImages:
    emit_build_step(1, 5, "rust-payload")
    payload = build_rust("vmsa-test-realm-stage2", log)
    emit_build_step(2, 5, "rmm")
    rmm = build_tf_rmm(repositories["tf-rmm"], log)
    emit_build_step(3, 5, "tf-a-tests")
    tftf = build_tftf(
        repositories["tf-a-tests"],
        None,
        log,
        test_suite="vmsa-realm",
        build_realm_payload=True,
        realm_payload_archive=payload,
    )
    emit_build_step(4, 5, "tf-a-firmware")
    images = build_tf_a(
        repositories["tf-a"],
        log,
        [
            "ENABLE_RME=1",
            "ARM_ARCH_MAJOR=9",
            "ARM_ARCH_MINOR=4",
            "ENABLE_FEAT_D128=2",
            "ENABLE_FEAT_AIE=1",
            f"RMM={rmm}",
            f"BL33={tftf}",
        ],
    )
    emit_build_step(5, 5, "package-cache")
    return images


def emit_build_step(index: int, total: int, name: str) -> None:
    print(f"VMSA-INFRA BUILD_STEP index={index} total={total} name={name}", flush=True)


def build(target: str, repositories: dict[str, Path]) -> FirmwareImages:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    log = OUTPUT / "firmware.log"
    prepare_target_workspace()
    ensure_rust(log)
    if target == "ns-el2":
        images = build_ns_el2(repositories, log)
    elif target == "secure-el2":
        images = build_secure_el2(repositories, log)
    elif target == "realm-el2":
        images = build_realm_el2(repositories, log)
    elif target == "realm-stage2":
        images = build_realm_stage2(repositories, log)
    elif target == "root-el3":
        images = build_root_el3(repositories, log)
    else:
        raise ValueError(f"unsupported target {target}")
    preserved = preserve_artifacts(target, repositories, images)
    validate_runtime_selector(preserved.fip)
    cache_build(target, preserved)
    return preserved


def preserve_artifacts(
    target: str,
    repositories: dict[str, Path],
    images: FirmwareImages,
) -> FirmwareImages:
    artifacts = OUTPUT / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    shutil.copy2(images.bl1, artifacts / "bl1.bin")
    shutil.copy2(images.fip, artifacts / "fip.bin")
    tf_a_build = repositories["tf-a"] / "build" / "fvp" / "debug"
    for relative in (
        Path("bl1/bl1.elf"),
        Path("bl1/bl1.map"),
        Path("bl2/bl2.elf"),
        Path("bl2/bl2.map"),
        Path("bl31/bl31.elf"),
        Path("bl31/bl31.map"),
        Path("rmm/rmm.elf"),
        Path("rmm/rmm.map"),
    ):
        source = tf_a_build / relative
        if source.is_file():
            shutil.copy2(source, artifacts / f"{target}-{source.name}")
    if target == "realm-stage2":
        rmm_build = repositories["tf-rmm"] / "build-vmsa"
        for name in ("rmm.elf",):
            matches = list(rmm_build.rglob(name))
            if len(matches) != 1:
                raise RuntimeError(f"expected one TF-RMM {name}, found {matches}")
            shutil.copy2(matches[0], artifacts / f"{target}-{name}")
    return FirmwareImages(artifacts / "bl1.bin", artifacts / "fip.bin")


def require_file(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError(f"required build artifact is missing: {path}")


if __name__ == "__main__":
    raise SystemExit("build.py is invoked by run.py")
