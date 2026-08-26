# Verified crate failures at e4fc0cd

## Level-sensitive VMSA64 and VMSA64-LPA2 output decoding

`descriptors.level-sensitive-address-decoding` constructs raw block address fields with a set
bit below the architectural block size, then calls the public stage-1 and stage-2
`DescriptorLayout::output_address(raw, level)` implementations for 4 KiB, 16 KiB, and 64 KiB
granules. The expected base is derived from the explicit aligned input and the architectural
level. On an unmodified `e4fc0cd`, the test reports 12 incorrect leaf results because both
formats ignore `level`; with the local correction it passes on FVP.

## Granule-offset bits survive public table-address decoding

The same test sets address-field bits below the 16 KiB and 64 KiB table alignment and calls the
public `DescriptorLayout::table_address`. On `e4fc0cd`, six stage/format cases return a
`TableAddr` containing those offset bits, contradicting the type's granule-alignment invariant.
The corrected crate masks the granule offset and the FVP test passes.

## Root table access ignores the configured input width

`geometry.compact-root-and-granule-levels` creates public `RootTableGeometry` for a 16 KiB,
48-bit, L0 root and supplies exactly two initialized descriptors through a public `TableAccess`
implementation. Those two entries are the complete architectural root because L0 selects VA
bit 47. On `e4fc0cd`, translations selecting both root entries fail because the walker requests
2048 entries. The corrected walker carries the root address width into its table shape and both
translations complete as invalid entries (`Ok(None)`).

## Root level validation is not granule aware

The geometry test also asks the public `RootTableGeometry::new_at_level` and
`TableShape::root` APIs for a VMSA64 64 KiB L0 root. L0 does not exist for this granule; L1 is
the lowest level needed within the 52-bit architectural input limit. Both calls incorrectly
succeed on `e4fc0cd` and reject L0 with the local correction. Together with the two compact-root
failures, the baseline test reports four failures and the corrected FVP run passes.

Commands used for the independent before/after check:

```text
vmsa-test test ns-el2 --crate <clean-e4fc0cd-snapshot> --filter level-sensitive-address-decoding
# wrong-value expected=0 actual=18
vmsa-test test ns-el2 --crate <clean-e4fc0cd-snapshot> --filter compact-root-and-granule-levels
# wrong-value expected=0 actual=4
vmsa-test test ns-el2 --crate /Users/boden/Documents/temp/Untitled/aarch64-vmsa --filter level-sensitive-address-decoding
# passed=1 failed=0
vmsa-test test ns-el2 --crate /Users/boden/Documents/temp/Untitled/aarch64-vmsa --filter compact-root-and-granule-levels
# passed=1 failed=0
```
