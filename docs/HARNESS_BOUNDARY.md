# Harness evidence boundary

The harness exists to supply memory, install architectural register state, execute accesses, and
normalize observations. It is not an implementation oracle for `aarch64-vmsa`.

## Crate evidence

A catalog result may count as crate evidence only when the behavior under assertion comes from a
public `aarch64-vmsa` API or from an architectural observation of data produced by that API. This
includes mapper construction and operations, descriptor construction and inspection, semantic
attribute resolution and decoding, table walking, invalidation callbacks, and typed crate errors.

Expected values must come from one of these independent sources:

- an architectural constant selected explicitly by the test;
- an FVP access, fault, `AT`/`PAR`, or cross-PE observation;
- a value derived by simple test arithmetic that does not reproduce the crate algorithm;
- an exact public crate error variant.

An encoder/decoder round trip is never sufficient architectural evidence by itself.

## Infrastructure only

The following harness behavior is infrastructure and must never be asserted as crate behavior:

- TCR, VTCR, TTBR, MAIR, MAIR2, PIR, and PIRE register installation and restoration;
- EL transitions, exception capture, FVP protocol, allocation, and runner isolation;
- conversion between harness result containers and protocol records;
- capability routing and watchdog behavior.

Register configuration accepts raw architectural encodings. In particular, the harness must not
encode `MemoryAttributes`; that belongs to the crate's `AttributeCodec`. Translation-control
helpers are permitted only to install a test context. Their return values must not be expected
values in a catalog assertion.

The private `infrastructure_stage1_start_level` check is a safety interlock before changing live
registers. Payload tests select their intended crate geometry explicitly and cannot call it.

## Raw mapping setup

`MappingAttributes` is a small fixture for creating otherwise uninteresting recovery and runtime
mappings. Its raw fields are inputs to the crate mapper, not expected outputs. Tests covering
permissions, memory attributes, descriptor controls, or semantic mapping must instead construct
the crate's typed semantic/raw values directly and inspect the crate-produced descriptor before
using hardware as the final oracle.

The synthetic `WalkerProbeFormat` supplies controlled inputs for generic public `Walker` error
paths. It is not evidence for any real descriptor format.

Run `python3 tools/validate_harness_boundary.py` with the other repository checks. The validator
rejects reintroduction of a harness memory-attribute encoder, exposure of the private start-level
interlock, and payload assertions whose expected side is sourced from register-setup helpers.
