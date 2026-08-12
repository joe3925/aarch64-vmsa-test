#![no_std]

pub type StageOf<R> = <R as aarch64_vmsa::regime::TranslationRegime>::Stage;
pub type LeafFieldsOf<F, R, G> = aarch64_vmsa::regime::RegimeLeafFields<F, R, G>;
pub type TableFieldsOf<F, R, G> = aarch64_vmsa::regime::RegimeTableFields<F, R, G>;

#[path = "../../common/access.rs"]
mod access;
#[path = "../../common/address_translation.rs"]
mod address_translation;
#[path = "../../common/alias_controls.rs"]
mod alias_controls;
#[path = "../../common/attributes.rs"]
mod attributes;
#[path = "../../common/attributes_live.rs"]
mod attributes_live;
#[path = "../../common/coherency.rs"]
mod coherency;
#[path = "../../common/combined_translation.rs"]
mod combined_translation;
#[path = "../../common/mod.rs"]
mod common;
#[path = "../../common/descriptors.rs"]
mod descriptors;
#[path = "../../common/faults.rs"]
mod faults;
#[path = "../../common/features.rs"]
mod features;
#[path = "../../common/formats_live.rs"]
mod formats_live;
#[path = "../../common/geometry.rs"]
mod geometry;
#[path = "../../common/hardware_updates.rs"]
mod hardware_updates;
#[path = "../../common/infrastructure.rs"]
mod infrastructure;
#[path = "../../common/invalidation.rs"]
mod invalidation;
#[path = "../../common/malformed_descriptors.rs"]
mod malformed_descriptors;
#[path = "../../common/mapper_live.rs"]
mod mapper_live;
#[path = "../../common/mapper_plans.rs"]
mod mapper_plans;
#[path = "../../common/metadata.rs"]
mod metadata;
#[path = "../../common/pas_nonsecure.rs"]
mod pas_nonsecure;
#[path = "../../common/permission_active.rs"]
mod permission_active;
#[path = "../../common/permission_semantic_cases.rs"]
mod permission_semantic_cases;
#[path = "../../common/permissions.rs"]
mod permissions;
#[path = "../../common/recovery.rs"]
mod recovery;
#[path = "../../common/runtime_support.rs"]
mod runtime_support;
#[path = "../../common/semantic_d128.rs"]
mod semantic_d128;
#[path = "../../common/semantic_host.rs"]
mod semantic_host;
#[path = "../../common/semantic_normal.rs"]
mod semantic_normal;
#[path = "../../common/stage2_leaf_matrix.rs"]
mod stage2_leaf_matrix;
#[path = "../../common/table_live.rs"]
mod table_live;

use common::{BootContext, REGIME_NORMAL, define_environment, outcome_code};
use vmsa_test_harness::adapter::{RunOptions, run_catalog_tests};
use vmsa_test_harness::{LogicalTest, Requirements, SecurityEnvironment, TestContext, TestResult};

define_environment!(
    NsEl2Environment,
    aarch64_vmsa::config::regime::NonSecureEl2Stage1
);
pub type CurrentEnvironment = NsEl2Environment;
pub type CurrentRegime = aarch64_vmsa::config::regime::NonSecureEl2Stage1;
pub type D128Regime = aarch64_vmsa::config::regime::NonSecureEl2HostStage1;
pub const fn current_d128_asid() -> Option<vmsa_test_harness::Asid> {
    Some(vmsa_test_harness::Asid(0x31))
}
pub const fn current_d128_controls(
    bits: vmsa_test_harness::AddressBits,
) -> Option<vmsa_test_harness::TranslationControls> {
    vmsa_test_harness::d128_el1_stage1_controls_4k(bits, bits)
}
pub type Stage2Regime = aarch64_vmsa::config::regime::NonSecureEl2Stage2;
pub type Stage2XnxRegime = aarch64_vmsa::config::regime::NonSecureEl2Stage2<
    aarch64_vmsa::config::stage2::Stage2XnxPermissions,
>;
pub type AlternateStage2Regime = aarch64_vmsa::config::regime::NonSecureEl2Stage2;
pub type AlternateStage2XnxRegime = aarch64_vmsa::config::regime::NonSecureEl2Stage2<
    aarch64_vmsa::config::stage2::Stage2XnxPermissions,
>;
pub type Stage2Pas = ();
pub const fn stage2_pas() -> Stage2Pas {}
pub type LowerRegime = aarch64_vmsa::config::regime::NonSecureEl1Stage1;
pub type HostRegime = aarch64_vmsa::config::regime::NonSecureEl2HostStage1;
pub type LowerPas = ();
pub type HostPas = ();
pub type HostTablePas = ();
pub type CurrentPas = ();
pub type CurrentTablePas = ();
pub const fn current_config_pas() -> CurrentPas {}
pub const fn current_pas() -> CurrentPas {}
pub const fn current_table_pas() -> CurrentTablePas {}
pub const fn alternate_current_pas() -> Option<CurrentPas> {
    None
}
pub const fn alternate_current_table_pas() -> Option<CurrentTablePas> {
    None
}
pub fn alternate_stage1_pas_fault(address: u64) -> vmsa_test_harness::FaultMatcher {
    vmsa_test_harness::FaultMatcher::new(
        vmsa_test_harness::ExpectedFault::translation_read_stage1(),
    )
    .with_class(vmsa_test_harness::FaultClass::DataAbort)
    .at_address(address)
}
pub const fn current_d128_alias() -> aarch64_vmsa::attrs::D128Stage1AliasKind {
    aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal
}
pub const fn current_regime_attributes() -> vmsa_test_harness::RegimeAttributes {
    vmsa_test_harness::RegimeAttributes::Normal
}
pub const fn lower_pas() -> LowerPas {}
pub const fn host_pas() -> HostPas {}
pub const fn host_table_pas() -> HostTablePas {}
pub const fn lower_regime_attributes() -> vmsa_test_harness::RegimeAttributes {
    vmsa_test_harness::RegimeAttributes::Normal
}
pub const fn host_regime_attributes() -> vmsa_test_harness::RegimeAttributes {
    vmsa_test_harness::RegimeAttributes::Normal
}

fn feature_snapshot_agreement(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::live_snapshot_agreement(context.capabilities())
}
fn security_state_membership(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::security_state_membership(
        context.capabilities(),
        aarch64_vmsa::arch::SecurityStates::NON_SECURE,
    )
}
fn regime_validation(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use aarch64_vmsa::config::regime::{
        NonSecureEl1Stage1, NonSecureEl2HostStage1, NonSecureEl2Stage1, NonSecureEl2Stage2,
    };
    use aarch64_vmsa::config::stage2::Stage2Permissions;
    use aarch64_vmsa::config::stage2::Stage2XnxPermissions;
    let current = aarch64_vmsa::arch::VmsaFeatures::current();
    features::regime_result(features::require_regimes!(&current;
        NonSecureEl2Stage1,
        NonSecureEl1Stage1,
        NonSecureEl2HostStage1,
        NonSecureEl2Stage2<Stage2Permissions>,
        NonSecureEl2Stage2<Stage2XnxPermissions>,
    ))
}
fn regime_format_validation(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    use aarch64_vmsa::config::regime::{
        NonSecureEl1Stage1, NonSecureEl2HostStage1, NonSecureEl2Stage1, NonSecureEl2Stage2,
    };
    use aarch64_vmsa::config::stage2::Stage2Permissions;
    use aarch64_vmsa::config::stage2::Stage2XnxPermissions;
    let current = &aarch64_vmsa::arch::VmsaFeatures::current();
    features::regime_result(
        features::require_all_formats!(current; NonSecureEl2Stage1)
            && features::require_all_formats!(current; NonSecureEl1Stage1)
            && features::require_all_formats!(current; NonSecureEl2HostStage1)
            && features::require_all_formats!(current; NonSecureEl2Stage2<Stage2Permissions>)
            && features::require_all_formats!(current; NonSecureEl2Stage2<Stage2XnxPermissions>),
    )
}
fn raw_field_bounds(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    descriptors::raw_field_bounds()
}
fn descriptor_errors(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    descriptors::descriptor_errors()
}
fn d128_stage1_final_bbm_nt_error(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    descriptors::d128_stage1_final_bbm_nt_error()
}
fn d128_stage2_final_bbm_nt_error(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    descriptors::d128_stage2_final_bbm_nt_error()
}
fn d128_stage1_table_nt_skl0_error(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    descriptors::d128_stage1_table_nt_skl0_error()
}
fn d128_stage2_table_nt_skl0_error(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    descriptors::d128_stage2_table_nt_skl0_error()
}
fn geometry_value_boundaries(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::value_boundaries()
}
fn geometry_level_spans(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::level_spans()
}
fn geometry_path_boundaries(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::path_boundaries()
}
fn walk_cursor_boundaries(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::walk_cursor_boundaries()
}
fn table_shape_transition_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::table_shape_transition_matrix()
}
fn invalid_table_levels(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::invalid_table_levels()
}
fn cursor_next_table_errors(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::cursor_next_table_errors()
}
fn vmsa64_output_width_acceptance(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::vmsa64_output_width_acceptance(context)
}
fn lpa2_output_width_acceptance(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::lpa2_output_width_acceptance(context)
}
fn d128_output_width_acceptance(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::d128_output_width_acceptance(context)
}
fn vmsa64_output_width_rejection(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::vmsa64_output_width_rejection(context)
}
fn lpa2_output_width_rejection(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::lpa2_output_width_rejection(context)
}
fn d128_output_width_rejection(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::d128_output_width_rejection(context)
}
fn vmsa64_root_address_bit_boundaries(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    geometry::vmsa64_root_address_bit_boundaries(context)
}
fn lpa2_root_address_bit_boundaries(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    geometry::lpa2_root_address_bit_boundaries(context)
}
fn d128_root_address_bit_boundaries(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    geometry::d128_root_address_bit_boundaries(context)
}
fn vmsa64_valid_root_levels(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::vmsa64_valid_root_levels(context)
}
fn lpa2_valid_root_levels(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::lpa2_valid_root_levels(context)
}
fn d128_valid_root_levels(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::d128_valid_root_levels(context)
}
fn vmsa64_invalid_root_levels(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::vmsa64_invalid_root_levels(context)
}
fn lpa2_invalid_root_levels(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::lpa2_invalid_root_levels(context)
}
fn d128_invalid_root_levels(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::d128_invalid_root_levels(context)
}
fn maximum_root_address(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::maximum_root_address(context)
}
fn unaligned_root_address(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::unaligned_root_address(context)
}
fn root_address_out_of_range(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    geometry::root_address_out_of_range(context)
}
fn mapper_step_by_one_plan(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_plans::step_by_one_plan()
}
fn mapper_bounded_skl_plan(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_plans::bounded_skl_plan()
}
fn mapper_maximum_skl_plan(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_plans::maximum_skl_plan()
}
fn mapper_bounded_skl_no_plan(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_plans::bounded_skl_no_plan()
}
fn mapper_max_skl_extended_root(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_plans::max_skl_extended_root()
}
fn mapper_d128_skl_transition_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_plans::d128_skl_transition_matrix()
}
fn mapper_map_leaf_with_step_by_one(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    mapper_plans::map_leaf_with_step_by_one(context)
}
fn mapper_map_leaf_with_bounded_skl(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    mapper_plans::map_leaf_with_bounded_skl(context)
}
fn mapper_map_leaf_with_maximum_skl(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    mapper_plans::map_leaf_with_maximum_skl(context)
}
macro_rules! mapper_parts_handler {
    ($name:ident) => {
        fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            mapper_plans::$name(context)
        }
    };
}
mapper_parts_handler!(offline_parts_s1_vmsa64_4k);
mapper_parts_handler!(offline_parts_s1_vmsa64_16k);
mapper_parts_handler!(offline_parts_s1_vmsa64_64k);
mapper_parts_handler!(offline_parts_s1_lpa2_4k);
mapper_parts_handler!(offline_parts_s1_lpa2_16k);
mapper_parts_handler!(offline_parts_s1_lpa2_64k);
mapper_parts_handler!(offline_parts_s1_d128_4k);
mapper_parts_handler!(offline_parts_s1_d128_16k);
mapper_parts_handler!(offline_parts_s1_d128_64k);
mapper_parts_handler!(offline_parts_s2_vmsa64_4k);
mapper_parts_handler!(offline_parts_s2_vmsa64_16k);
mapper_parts_handler!(offline_parts_s2_vmsa64_64k);
mapper_parts_handler!(offline_parts_s2_lpa2_4k);
mapper_parts_handler!(offline_parts_s2_lpa2_16k);
mapper_parts_handler!(offline_parts_s2_lpa2_64k);
mapper_parts_handler!(offline_parts_s2_d128_4k);
mapper_parts_handler!(offline_parts_s2_d128_16k);
mapper_parts_handler!(offline_parts_s2_d128_64k);
mapper_parts_handler!(live_parts_s1_vmsa64_4k);
mapper_parts_handler!(live_parts_s1_vmsa64_16k);
mapper_parts_handler!(live_parts_s1_vmsa64_64k);
mapper_parts_handler!(live_parts_s1_lpa2_4k);
mapper_parts_handler!(live_parts_s1_lpa2_16k);
mapper_parts_handler!(live_parts_s1_lpa2_64k);
mapper_parts_handler!(live_parts_s1_d128_4k);
mapper_parts_handler!(live_parts_s1_d128_16k);
mapper_parts_handler!(live_parts_s1_d128_64k);
mapper_parts_handler!(live_parts_s2_vmsa64_4k);
mapper_parts_handler!(live_parts_s2_vmsa64_16k);
mapper_parts_handler!(live_parts_s2_vmsa64_64k);
mapper_parts_handler!(live_parts_s2_lpa2_4k);
mapper_parts_handler!(live_parts_s2_lpa2_16k);
mapper_parts_handler!(live_parts_s2_lpa2_64k);
mapper_parts_handler!(live_parts_s2_d128_4k);
mapper_parts_handler!(live_parts_s2_d128_16k);
mapper_parts_handler!(live_parts_s2_d128_64k);
fn stage1_single_permission_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::stage1_single_matrix()
}
fn stage1_two_privilege_permission_matrix(
    _: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    permissions::stage1_two_privilege_matrix()
}
fn stage2_direct_permission_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::stage2_direct_matrix()
}
fn d128_stage2_base_permission_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::d128_stage2_base_matrix()
}
fn d128_stage2_overlay_permission_matrix(
    _: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    permissions::d128_stage2_overlay_matrix()
}
fn d128_stage1_indirection_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::d128_stage1_indirection_matrix()
}
fn d128_stage1_indirection_unavailable(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::d128_stage1_indirection_unavailable()
}
fn d128_stage1_missing_combination(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::d128_stage1_missing_combination()
}
fn d128_stage1_duplicate_selection(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::d128_stage1_duplicate_selection()
}
fn d128_stage1_conflicting_permissions(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::d128_stage1_conflicting_permissions()
}
fn d128_stage2_indirection_unavailable(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::d128_stage2_indirection_unavailable()
}
fn d128_stage2_missing_combination(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::d128_stage2_missing_combination()
}
fn d128_stage2_duplicate_selection(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::d128_stage2_duplicate_selection()
}
fn invalid_fixed_output_address_space(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::invalid_fixed_output_address_space()
}
fn invalid_d128_alias(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::invalid_d128_alias()
}
fn invalid_d128_final_level_nt(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::invalid_d128_final_level_nt()
}
fn conflicting_stage1_semantics(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permissions::conflicting_stage1_semantics()
}
fn vmsa64_software_metadata_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    metadata::vmsa64_four_bit()
}
fn d128_stage1_software_metadata_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    metadata::d128_stage1_ten_bit()
}
fn d128_stage2_software_metadata_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    metadata::d128_stage2_ten_bit()
}
fn mair_device_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    attributes::mair_device_matrix()
}
fn mair_normal_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    attributes::mair_normal_matrix()
}
fn mair_error_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    attributes::mair_error_matrix()
}
fn stage2_combined_memory_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    attributes::stage2_combined_matrix()
}
fn stage2_fwb_memory_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    attributes::stage2_fwb_matrix()
}
fn d128_mair2_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    attributes::d128_mair2_matrix()
}
fn lpa2_shareability_matrix(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    attributes::lpa2_shareability_matrix()
}
fn feature_requirement_unions(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::requirement_unions()
}
fn feature_decode_binary(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::decode_binary_raw_encodings()
}
fn feature_decode_exception_levels(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::decode_exception_level_raw_encodings()
}
fn feature_decode_rme(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::decode_rme_raw_encodings()
}
fn feature_decode_varange(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::decode_varange_raw_encodings()
}
fn feature_decode_parange(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::decode_parange_raw_encodings()
}
fn feature_decode_lpa2_tg4(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::decode_lpa2_tg4_raw_encodings()
}
fn feature_decode_lpa2_tg16(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::decode_lpa2_tg16_raw_encodings()
}
fn feature_decode_lpa2_secondary(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::decode_lpa2_secondary_raw_encodings()
}
fn feature_decode_lpa2_priority(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::decode_lpa2_priority()
}
fn feature_decode_derived_merge(_: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    features::decode_derived_merge_orderings()
}

fn current_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    access::current_access(context)
}
fn current_fault(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    faults::current_fault(context)
}
fn access_widths(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    access::access_widths(context)
}
fn pair_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    access::pair_access(context)
}
fn ordered_atomic_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    access::ordered_atomic_access(context)
}
fn address_translation(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    address_translation::address_translation(context)
}
fn lower_address_translation(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    address_translation::lower_address_translation(
        context,
        vmsa_test_harness::RegimeAttributes::Normal,
    )
}
fn generated_execution(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    coherency::generated_execution(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn live_range_mapping(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::live_range_mapping(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn exact_block_outcome(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::exact_block_outcome(context)
}
fn exact_page_outcome(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::exact_page_outcome(context)
}
fn block_page_boundary(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::block_page_boundary(context)
}
fn terminal_table_growth_boundary(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::terminal_table_growth_boundary(context)
}
fn maximum_input_page(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::maximum_input_page(context)
}
fn one_past_input_page(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::one_past_input_page(context)
}
fn maximum_output_page(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::maximum_output_page(context)
}
fn one_past_output_page(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::one_past_output_page(context)
}
fn unaligned_leaf_input(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::unaligned_leaf_input(context)
}
fn unaligned_leaf_output(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::unaligned_leaf_output(context)
}
fn leaf_level_below_root(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::leaf_level_below_root(context)
}
fn leaf_level_past_final(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::leaf_level_past_final(context)
}
fn already_mapped_leaf(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::already_mapped_leaf(context)
}
fn already_mapped_table(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::already_mapped_table(context)
}
fn not_mapped_translate(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::not_mapped_translate(context)
}
fn not_mapped_unmap(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::not_mapped_unmap(context)
}
fn not_mapped_reclaim(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::not_mapped_reclaim(context)
}
fn non_leaf_base_unmap(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::non_leaf_base_unmap(context)
}
fn reclaim_sibling_lifecycle(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::reclaim_sibling_lifecycle(context)
}
fn live_reclaim_outcome(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::live_reclaim_outcome(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn live_reclaim_post_fault(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::live_reclaim_post_fault(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn frame_provider_error(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::frame_provider_error(context)
}
fn map_leaf_partial_table_path(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::map_leaf_partial_table_path(context)
}
fn multi_pe_visibility(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    coherency::multi_pe_translation_visibility(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn live_break_before_make(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::live_break_before_make(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn semantic_codec(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    attributes_live::semantic_codec(context)
}
fn missing_memory_attribute(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    attributes_live::missing_memory_attribute(context)
}
fn stage1_semantic_mapper(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permission_semantic_cases::stage1_semantic_mapper(context)
}
fn stage2_direct_semantic_mapper(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permission_semantic_cases::stage2_direct_semantic_mapper(context)
}
fn stage2_fwb_semantic_mapper(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permission_semantic_cases::stage2_fwb_semantic_mapper(context)
}
fn d128_stage2_semantic_mapper(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    permission_semantic_cases::d128_stage2_semantic_mapper(context)
}
fn d128_stage1_effective_semantic_mapper(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    permission_semantic_cases::d128_stage1_effective_semantic_mapper(context)
}
fn recursive_table_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::recursive_table_access(context)
}
fn translation_table_read_write(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::translation_table_read_write(context)
}
fn walker_invalid_agreement(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::walker_invalid_agreement(context)
}
fn walker_block_agreement(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::walker_block_agreement(context)
}
fn walker_table_page_agreement(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::walker_table_page_agreement(context)
}
fn walker_access_error(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::walker_access_error(context)
}
fn walker_access_location_error(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::walker_access_location_error(context)
}
fn walker_cursor_error(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::walker_cursor_error(context)
}
fn walker_invalid_table_address_error(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    table_live::walker_invalid_table_address_error(context)
}
fn walker_entry_index_error(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::walker_entry_index_error(context)
}
fn walker_final_table_error(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::walker_final_table_error(context)
}
fn walker_output_overflow_error(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::walker_output_overflow_error(context)
}
fn recursive_index_error(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::recursive_index_error(context)
}
fn recursive_base_errors(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::recursive_base_errors(context)
}
fn recursive_level_error(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::recursive_level_error(context)
}
fn recursive_path_errors(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    table_live::recursive_path_errors(context)
}
fn allocation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::allocation_failure(context)
}
fn page_allocation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::page_allocation_failure(context)
}
fn contiguous_allocation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::contiguous_allocation_failure(context)
}
fn root_allocation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::root_allocation_failure(context)
}
fn table_allocation_failure_0(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::table_allocation_failure_0(context)
}
fn table_allocation_failure_1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::table_allocation_failure_1(context)
}
fn table_allocation_failure_2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::table_allocation_failure_2(context)
}
fn mapper_map_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::mapper_map_failure(context)
}
fn mapper_range_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::mapper_range_failure(context)
}
fn mapper_remap_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::mapper_remap_failure(context)
}
fn mapper_protect_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::mapper_protect_failure(context)
}
fn mapper_unmap_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::mapper_unmap_failure(context)
}
fn mapper_reclaim_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::mapper_reclaim_failure(context)
}
fn current_installation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::current_installation_failure(context)
}
fn lower_installation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::lower_installation_failure(context)
}
fn partial_combined_installation_failure(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    recovery::partial_combined_installation_failure(context)
}
fn lower_entry_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::lower_entry_failure(context)
}
fn lower_action_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::lower_action_failure(context)
}
fn lower_return_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::lower_return_failure(context)
}
fn secondary_start_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::secondary_start_failure(context)
}
fn secondary_rendezvous_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::secondary_rendezvous_failure(context)
}
fn secondary_action_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::secondary_action_failure(context)
}
fn secondary_timeout_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::secondary_timeout_failure(context)
}
fn secondary_stop_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::secondary_stop_failure(context)
}
fn invalidation_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::invalidation_failure(context)
}
fn barrier_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::barrier_failure(context)
}
fn tlbi_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::tlbi_failure(context)
}
fn explicit_restore_failure(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::explicit_restore_failure(context)
}
fn drop_restore(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::drop_restore(context)
}
fn emergency_restore(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    recovery::emergency_restore(context)
}
fn lower_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    access::lower_access(context)
}
fn lower_fault(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    faults::lower_fault_expected(
        context,
        vmsa_test_harness::ExpectedFault {
            status: Some(vmsa_test_harness::FaultStatus::External),
            access: Some(vmsa_test_harness::AccessKind::Read),
            stage: None,
            level: None,
        },
    )
}
fn el0_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    access::el0_access(context)
}
fn el2_el0_access(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    access::el2_el0_host_atomic_access(context)
}
fn lpa2_mapper(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::mapper_lpa2(context)
}
fn d128_mapper(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::mapper_d128(context)
}
fn translation_cycle(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    invalidation::stage1_translation_cycle(context, vmsa_test_harness::RegimeAttributes::Normal)
}
fn stage2_translation_cycle(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    invalidation::stage2_translation_cycle::<_, Stage2Regime>(
        context,
        vmsa_test_harness::RegimeAttributes::Normal,
    )
}
fn asid_isolation(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    invalidation::lower_stage1_asid_isolation::<CurrentEnvironment, LowerRegime>(
        context,
        vmsa_test_harness::RegimeAttributes::Normal,
    )
}
fn vmid_isolation(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    invalidation::stage2_vmid_isolation::<_, Stage2Regime>(
        context,
        vmsa_test_harness::RegimeAttributes::Normal,
    )
}
fn combined_stage1_stage2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    combined_translation::combined_stage1_stage2(context)
}
macro_rules! formats_live_handler {
    ($name:ident) => {
        fn $name(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            formats_live::$name(context)
        }
    };
}

formats_live_handler!(active_vmsa64_4k_l1);
formats_live_handler!(active_vmsa64_4k_l1_at);
formats_live_handler!(active_vmsa64_4k_l2);
formats_live_handler!(active_vmsa64_4k_l2_at);
formats_live_handler!(active_vmsa64_4k_l3);
formats_live_handler!(active_vmsa64_4k_l3_at);
formats_live_handler!(active_vmsa64_16k_l2);
formats_live_handler!(active_vmsa64_16k_l2_at);
formats_live_handler!(active_vmsa64_16k_l3);
formats_live_handler!(active_vmsa64_16k_l3_at);
formats_live_handler!(active_vmsa64_64k_l2);
formats_live_handler!(active_vmsa64_64k_l2_at);
formats_live_handler!(active_vmsa64_64k_l3);
formats_live_handler!(active_vmsa64_64k_l3_at);
formats_live_handler!(active_lpa2_4k_l0);
formats_live_handler!(active_lpa2_4k_l0_at);
formats_live_handler!(active_lpa2_4k_l1);
formats_live_handler!(active_lpa2_4k_l1_at);
formats_live_handler!(active_lpa2_4k_l2);
formats_live_handler!(active_lpa2_4k_l2_at);
formats_live_handler!(active_lpa2_4k_l3);
formats_live_handler!(active_lpa2_4k_l3_at);
formats_live_handler!(active_lpa2_16k_l1);
formats_live_handler!(active_lpa2_16k_l1_at);
formats_live_handler!(active_lpa2_16k_l2);
formats_live_handler!(active_lpa2_16k_l2_at);
formats_live_handler!(active_lpa2_16k_l3);
formats_live_handler!(active_lpa2_16k_l3_at);
formats_live_handler!(active_lpa2_64k_l1);
formats_live_handler!(active_lpa2_64k_l1_at);
formats_live_handler!(active_lpa2_64k_l2);
formats_live_handler!(active_lpa2_64k_l2_at);
formats_live_handler!(active_lpa2_64k_l3);
formats_live_handler!(active_lpa2_64k_l3_at);
fn active_stage2_vmsa64_4k_l1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::vmsa64_l1(context)
}
fn active_stage2_vmsa64_4k_l2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::vmsa64_l2(context)
}
fn active_stage2_vmsa64_4k_l3(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::vmsa64_l3(context)
}
fn active_stage2_lpa2_4k_l0(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::lpa2_l0(context)
}
fn active_stage2_lpa2_4k_l1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::lpa2_l1(context)
}
fn active_stage2_lpa2_4k_l2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::lpa2_l2(context)
}
fn active_stage2_lpa2_4k_l3(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::lpa2_l3(context)
}
fn active_stage2_vmsa64_4k_l1_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::vmsa64_l1_at(context)
}
fn active_stage2_vmsa64_4k_l2_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::vmsa64_l2_at(context)
}
fn active_stage2_vmsa64_4k_l3_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::vmsa64_l3_at(context)
}
fn active_stage2_lpa2_4k_l0_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::lpa2_l0_at(context)
}
fn active_stage2_lpa2_4k_l1_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::lpa2_l1_at(context)
}
fn active_stage2_lpa2_4k_l2_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::lpa2_l2_at(context)
}
fn active_stage2_lpa2_4k_l3_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::lpa2_l3_at(context)
}
fn active_stage2_d128_4k_l0(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::d128_l0(context)
}
fn active_stage2_d128_4k_l1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::d128_l1(context)
}
fn active_stage2_d128_4k_l2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::d128_l2(context)
}
fn active_stage2_d128_4k_l3(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::d128_l3(context)
}
fn active_stage2_d128_4k_l0_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::d128_l0_at(context)
}
fn active_stage2_d128_4k_l1_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::d128_l1_at(context)
}
fn active_stage2_d128_4k_l2_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::d128_l2_at(context)
}
fn active_stage2_d128_4k_l3_at(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    stage2_leaf_matrix::d128_l3_at(context)
}
macro_rules! stage2_matrix_handler {
    ($handler:ident, $case:ident) => {
        fn $handler(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
            stage2_leaf_matrix::$case(context)
        }
    };
}
stage2_matrix_handler!(active_stage2_vmsa64_16k_l2, vmsa64_16k_l2);
stage2_matrix_handler!(active_stage2_vmsa64_16k_l3, vmsa64_16k_l3);
stage2_matrix_handler!(active_stage2_vmsa64_16k_l2_at, vmsa64_16k_l2_at);
stage2_matrix_handler!(active_stage2_vmsa64_16k_l3_at, vmsa64_16k_l3_at);
stage2_matrix_handler!(active_stage2_vmsa64_64k_l2, vmsa64_64k_l2);
stage2_matrix_handler!(active_stage2_vmsa64_64k_l3, vmsa64_64k_l3);
stage2_matrix_handler!(active_stage2_vmsa64_64k_l2_at, vmsa64_64k_l2_at);
stage2_matrix_handler!(active_stage2_vmsa64_64k_l3_at, vmsa64_64k_l3_at);
stage2_matrix_handler!(active_stage2_lpa2_16k_l1, lpa2_16k_l1);
stage2_matrix_handler!(active_stage2_lpa2_16k_l2, lpa2_16k_l2);
stage2_matrix_handler!(active_stage2_lpa2_16k_l3, lpa2_16k_l3);
stage2_matrix_handler!(active_stage2_lpa2_16k_l1_at, lpa2_16k_l1_at);
stage2_matrix_handler!(active_stage2_lpa2_16k_l2_at, lpa2_16k_l2_at);
stage2_matrix_handler!(active_stage2_lpa2_16k_l3_at, lpa2_16k_l3_at);
stage2_matrix_handler!(active_stage2_lpa2_64k_l1, lpa2_64k_l1);
stage2_matrix_handler!(active_stage2_lpa2_64k_l2, lpa2_64k_l2);
stage2_matrix_handler!(active_stage2_lpa2_64k_l3, lpa2_64k_l3);
stage2_matrix_handler!(active_stage2_lpa2_64k_l1_at, lpa2_64k_l1_at);
stage2_matrix_handler!(active_stage2_lpa2_64k_l2_at, lpa2_64k_l2_at);
stage2_matrix_handler!(active_stage2_lpa2_64k_l3_at, lpa2_64k_l3_at);
stage2_matrix_handler!(active_stage2_d128_16k_l1, d128_16k_l1);
stage2_matrix_handler!(active_stage2_d128_16k_l2, d128_16k_l2);
stage2_matrix_handler!(active_stage2_d128_16k_l3, d128_16k_l3);
stage2_matrix_handler!(active_stage2_d128_16k_l1_at, d128_16k_l1_at);
stage2_matrix_handler!(active_stage2_d128_16k_l2_at, d128_16k_l2_at);
stage2_matrix_handler!(active_stage2_d128_16k_l3_at, d128_16k_l3_at);
stage2_matrix_handler!(active_stage2_d128_64k_l1, d128_64k_l1);
stage2_matrix_handler!(active_stage2_d128_64k_l2, d128_64k_l2);
stage2_matrix_handler!(active_stage2_d128_64k_l3, d128_64k_l3);
stage2_matrix_handler!(active_stage2_d128_64k_l1_at, d128_64k_l1_at);
stage2_matrix_handler!(active_stage2_d128_64k_l2_at, d128_64k_l2_at);
stage2_matrix_handler!(active_stage2_d128_64k_l3_at, d128_64k_l3_at);
formats_live_handler!(active_d128_4k_l0);
formats_live_handler!(active_d128_4k_l1);
formats_live_handler!(active_d128_4k_l2);
formats_live_handler!(active_d128_4k_l3);
formats_live_handler!(active_d128_4k_l0_at);
formats_live_handler!(active_d128_4k_l1_at);
formats_live_handler!(active_d128_4k_l2_at);
formats_live_handler!(active_d128_4k_l3_at);
formats_live_handler!(active_d128_16k_l1);
formats_live_handler!(active_d128_16k_l2);
formats_live_handler!(active_d128_16k_l3);
formats_live_handler!(active_d128_16k_l1_at);
formats_live_handler!(active_d128_16k_l2_at);
formats_live_handler!(active_d128_16k_l3_at);
formats_live_handler!(active_d128_64k_l1);
formats_live_handler!(active_d128_64k_l2);
formats_live_handler!(active_d128_64k_l3);
formats_live_handler!(active_d128_64k_l1_at);
formats_live_handler!(active_d128_64k_l2_at);
formats_live_handler!(active_d128_64k_l3_at);
fn mapper_16k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::mapper_16k(context)
}
fn mapper_64k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    mapper_live::mapper_64k(context)
}

fn active_16k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    formats_live::active_16k(context)
}
fn malformed_vmsa64_reserved_type(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::vmsa64_reserved_type(context)
}
fn malformed_vmsa64_res0(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::vmsa64_res0(context)
}
fn malformed_vmsa64_res1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::vmsa64_res1(context)
}
fn malformed_lpa2_ds_reserved_type(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    malformed_descriptors::lpa2_ds_reserved_type(context)
}
fn malformed_lpa2_ds_address(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::lpa2_ds_address(context)
}
fn malformed_lpa2_ds_res0(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::lpa2_ds_res0(context)
}
fn malformed_lpa2_ds_res1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::lpa2_ds_res1(context)
}
fn malformed_lpa2_64k_reserved_type(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    malformed_descriptors::lpa2_64k_reserved_type(context)
}
fn malformed_lpa2_64k_address(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::lpa2_64k_address(context)
}
fn malformed_lpa2_64k_res0(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::lpa2_64k_res0(context)
}
fn malformed_lpa2_64k_res1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::lpa2_64k_res1(context)
}
fn malformed_d128_valid_res1(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::d128_valid_res1(context)
}
fn malformed_d128_skl(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::d128_skl(context)
}
fn malformed_d128_address(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::d128_address(context)
}
fn malformed_d128_res0(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    malformed_descriptors::d128_res0(context)
}
fn active_4k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    formats_live::active_4k(context)
}
fn active_64k(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    formats_live::active_64k(context)
}
fn active_lpa2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    formats_live::active_lpa2(context)
}
fn active_d128(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    formats_live::active_d128(context)
}
fn active_d128_stage2(context: &mut TestContext<'_, CurrentEnvironment>) -> TestResult {
    formats_live::active_d128_stage2(context)
}
fn infrastructure_d128_stage1_register_restoration(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    infrastructure::d128_stage1_register_restoration(context)
}
fn infrastructure_following_stage1_access(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    infrastructure::following_stage1_access(context)
}
macro_rules! dispatch_handler {
    ($context:ident, (none)) => {
        return None
    };
    ($context:ident, ($handler:path)) => {
        $handler($context)
    };
}
macro_rules! define_normal_dispatch {
    ($($variant:ident, $name:literal, $builder:ident($($argument:expr),*), $normal:tt, $secure:tt, $realm:tt, $rec:tt, $root:tt;)*) => {
        fn dispatch(test: LogicalTest, context: &mut TestContext<'_, CurrentEnvironment>) -> Option<TestResult> {
            Some(match test { $(LogicalTest::$variant => dispatch_handler!(context, $normal),)* })
        }
    };
}
vmsa_test_harness::for_each_registered_test!(define_normal_dispatch);

#[unsafe(no_mangle)]
/// Enters the Normal-world EL2 harness from the firmware integration shim.
///
/// # Safety
///
/// `context` must point to a readable `BootContext` that remains valid until return.
pub unsafe extern "C" fn vmsa_test_ns_el2_entry(context: *const BootContext) -> u32 {
    let Ok(context) = (unsafe { BootContext::from_abi(context) }) else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    if context.lower_el_entry != vmsa_test_lower_el::entry_address() {
        return common::ENTRY_INVALID_CONTEXT;
    }
    let Ok((mut environment, filter)) = CurrentEnvironment::from_boot(context, REGIME_NORMAL)
    else {
        return common::ENTRY_INVALID_CONTEXT;
    };
    outcome_code(run_catalog_tests(
        &mut environment,
        SecurityEnvironment::Normal,
        dispatch,
        RunOptions {
            target: "ns-el2",
            profile: vmsa_test_harness::BootProfile::NsEl2,
            filter,
            baseline: Requirements::NONE,
        },
    ))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    common::handle_panic()
}
