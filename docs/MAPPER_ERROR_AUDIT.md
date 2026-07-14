# `MapperError` variant and payload audit

Tested crate revision: `ada32824cd813c16ab6ea30322ee396aad3aaa75`.

This audit distinguishes errors reachable through a valid public `Mapper` and the
arena-backed test providers from errors that require a deliberately malformed
provider, table location, cursor, or descriptor. “Constructor gate” means
`Mapper::new_offline` rejects the state before an operation can reach the named
variant. “Validated provider invariant” means the safe harness owns and checks
the state that the crate's unsafe provider contract requires.

| `MapperError` variant | Payload fields | Exact evidence or classification |
|---|---|---|
| `Access` | provider `AccessError` | The arena `OffsetTableAccess` offset and every table frame come from the same checked allocation arena. Address overflow/null mappings require violating that provider invariant; the underlying `AccessError` payload matrix is covered by `tables.recursive-access`, `geometry.path-boundaries`, and `walk.cursor-boundaries`. |
| `Frame` | provider `MemoryError` | `mapper.frame-provider-error` asserts `Frame(InjectedFailure)`, then verifies no mapping, retries, and translates successfully. Other `MemoryError` values are allocator-state errors tested by `recovery.allocation-failure`; they cannot be produced by a valid mapper-owned frame lifecycle without violating the provider contract. |
| `AccessLocation` | every `AccessError` payload | Explicit malformed-provider classification. Valid `WalkCursor`/`TableAccessLocation` construction prevents these states. Exact field boundaries are exercised in `geometry.path-boundaries`, `walk.cursor-boundaries`, and `tables.recursive-access`. |
| `Table` | `EntryIndexOutOfRange { index, entries }` | Public-unreachable with a cursor and table shape from the same `TableGeometry`; exact index/entry boundaries are covered by `walk.cursor-boundaries`. |
| `TableAddress` | `Unaligned { addr, align }` | Requires a malformed table descriptor. Raw malformed descriptors are isolated from viable mapper tests; exact address/alignment behavior is covered by `descriptors.exact-errors` and the separate-boot malformed recovery case. |
| `Descriptor` | all `DescriptorError` variants and fields | Exact payload coverage is owned by `descriptors.exact-errors`, `attributes.invalid-d128-final-level-nt`, and `descriptors.d128-reserved-rejection`. Normal semantic/raw mapper entry points cannot manufacture invalid typed fields. |
| `Cursor` | `InvalidRootLevel { root_level, lowest_level, final_level }`; `InvalidLevel { level }` | Constructor-gated or malformed-cursor-only. Constructor payloads are asserted by the three `mapper.*-invalid-root-levels` cases; cursor payloads are asserted by `walk.cursor-boundaries`. |
| `InvalidRootLevel` | `root_level`, `lowest_level`, `final_level` | Exact for VMSA64, LPA2, and D128 in the three `mapper.*-invalid-root-levels` identities. |
| `InvalidRootAddressBits` | `addr_bits`, `max_addr_bits` | Exact lower/upper boundaries for all three formats in the three `mapper.*-root-address-bit-boundaries` identities. |
| `InvalidLeafLevel` | `level`, `root_level`, `final_level` | Exact before-root, after-final, and unsupported leaf levels in `mapper.invalid-leaf-levels`. |
| `InputAddressOutOfRange` | `addr`, `addr_bits` | Exact single-leaf and range-end payloads in `mapper.one-past-input-page` and `mapper.input-range-end-out-of-range`. |
| `AddressOverflow` | no payload | Exact in `mapper.input-range-arithmetic-overflow`. Counter overflows inside a successful `map_range` require more than `u64::MAX` mappings and are unreachable before input-length validation. |
| `InvalidLevel` | `level` | Public operation classification: `map_leaf`/`map_range` call `require_leaf_level` first and therefore return `InvalidLeafLevel`; translated descriptors at L3 decode as page/invalid rather than table for every public format. The remaining source path requires a custom malformed `DescriptorLayout`, which is outside the sealed format set. |
| `OutputAddressOverflow` | `base`, `offset` | Exact in `mapper.output-range-arithmetic-overflow`. |
| `InvalidConfiguredOutputAddressBits` | `output_address_bits`, `format_max_bits` | Exact acceptance/rejection identities for VMSA64, LPA2, and D128. This is constructor-only after successful construction. |
| `OutputAddressOutOfRange` | `addr`, `output_address_bits` | Exact in `mapper.one-past-output-page`, plus root-address construction in `mapper.root-address-out-of-range`. |
| `UnalignedInput` | `addr`, `align` | Exact leaf and range payloads in `mapper.unaligned-leaf-input` and `mapper.unaligned-range-input`. |
| `UnalignedOutput` | `addr`, `align` | Exact leaf and range payloads in `mapper.unaligned-leaf-output` and `mapper.unaligned-range-output`. |
| `LengthNotMappingMultiple` | `len`, `mapping_size` | Exact in `mapper.invalid-range-length`. |
| `InputNotLeafBase` | `input`, `covered_input_base`, `covered_size`, `level` | Exact in `mapper.non-leaf-base-unmap`. |
| `AlreadyMapped` | `input`, `level`, `entry_index` | Exact table and leaf collisions in `mapper.already-mapped-table` and `mapper.already-mapped-leaf`. |
| `NotMapped` | `input` | Independently exact for translate, unmap, and reclaim in the three `mapper.not-mapped-*` identities. |

No row is closed by swallowing a variant into a generic success path. Provider-
contract classifications identify the prerequisite invalid state and the
separate lower-level test family that owns its exact payload boundaries.
