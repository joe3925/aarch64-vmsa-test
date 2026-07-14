use crate::{CurrentEnvironment, LowerRegime, Stage2Regime};
use vmsa_test_harness::{TestContext, TestResult};

pub(super) fn combined_stage1_stage2(
    context: &mut TestContext<'_, CurrentEnvironment>,
) -> TestResult {
    use vmsa_test_harness::{
        AddressBits, Asid, Granule, LookupLevel, MappingAttributes, PhysicalAddress,
        TranslationFormat, TranslationQueryAccess, TranslationQueryResult, TranslationSetup,
        TranslationStage, Vmid, vmsa64_el1_stage1_controls_4k, vmsa64_stage2_controls_4k,
    };

    const VIRTUAL_ADDRESS: u64 = 0x5000_0000;
    let input_bits = AddressBits::new(39).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let output_width = context.capabilities().pa_bits.min(48);
    let output_bits =
        AddressBits::new(output_width).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let start_level = LookupLevel::new(1).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let level3 = LookupLevel::new(3).ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage1_controls = vmsa64_el1_stage1_controls_4k(input_bits, output_bits)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let stage2_controls = vmsa64_stage2_controls_4k(input_bits, output_bits, start_level)
        .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
    let cacheability = aarch64_vmsa::attrs::Cacheability::Cacheable {
        policy: aarch64_vmsa::attrs::CachePolicy::WriteBack,
        transience: aarch64_vmsa::attrs::MemoryTransience::NonTransient,
        allocation: aarch64_vmsa::attrs::AllocationHints::ReadWriteAllocate,
    };
    let stage1_memory = vmsa_test_harness::Stage1MemoryControls::DEFAULT
        .with_attribute(
            vmsa_test_harness::MemoryAttributeSlot::new(0)
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?,
            aarch64_vmsa::attrs::MemoryAttributes::Normal {
                inner: cacheability,
                outer: cacheability,
            },
        )
        .map_err(vmsa_test_harness::HarnessError::Attribute)?;

    for mode in 1u16..3 {
        let omit_target = mode == 2;
        let data_page = context.allocate_page()?;
        const DATA_VALUE: u64 = 0x434f_4d42_494e_4544;
        if !matches!(
            context.write_u64(data_page.virtual_address() as u64, DATA_VALUE),
            vmsa_test_harness::AccessResult::Completed { .. }
        ) {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        let mut stage1_root = context.allocate_root()?;
        let mut stage2_root = context.allocate_root()?;
        let table_walk_region = stage1_root.phys_addr() & !0x3fff_ffff;
        let target_region = table_walk_region ^ 0x4000_0000;
        let target_ipa = target_region | (data_page.phys_addr() - table_walk_region);
        {
            let mut mapper = context.offline_mapper_for_format_with_geometry::<
                LowerRegime,
                aarch64_vmsa::address::Granule4KiB,
                aarch64_vmsa::descriptor::Vmsa64,
            >(
                &mut stage1_root,
                aarch64_vmsa::address::Level::L1,
                input_bits.get(),
                output_bits.get(),
            )?;
            mapper.map_leaf(
                VIRTUAL_ADDRESS,
                target_ipa,
                level3,
                MappingAttributes::READ_WRITE,
            )?;
            let inspection = mapper
                .translate(VIRTUAL_ADDRESS)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if inspection.output != target_ipa {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
        }
        {
            let mut mapper = context.offline_mapper_for_format_with_geometry::<
                Stage2Regime,
                aarch64_vmsa::address::Granule4KiB,
                aarch64_vmsa::descriptor::Vmsa64,
            >(
                &mut stage2_root,
                aarch64_vmsa::address::Level::L1,
                input_bits.get(),
                output_bits.get(),
            )?;
            let recovery_attributes = MappingAttributes {
                writable: true,
                executable: true,
                user_accessible: false,
            };
            mapper.map_leaf(
                table_walk_region,
                table_walk_region,
                start_level,
                recovery_attributes,
            )?;
            // The lower-EL firmware conduit and its fault mailbox live in the
            // low 1 GiB IPA region. Keep that invariant recovery path reachable
            // while stage 2 is active so a candidate-target fault can return.
            mapper.map_leaf(0, 0, start_level, recovery_attributes)?;
            if !omit_target {
                mapper.map_leaf(
                    target_region,
                    table_walk_region,
                    start_level,
                    MappingAttributes::READ_WRITE,
                )?;
            }
        }
        let stage1_setup = TranslationSetup {
            root: PhysicalAddress::new(stage1_root.phys_addr()),
            stage: TranslationStage::Stage1,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: Some(start_level),
            asid: Some(Asid(0x40 + mode)),
            vmid: None,
            controls: stage1_controls,
            stage1_memory,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        };
        let stage2_setup = TranslationSetup {
            root: PhysicalAddress::new(stage2_root.phys_addr()),
            stage: TranslationStage::Stage2,
            granule: Granule::Size4KiB,
            format: TranslationFormat::Vmsa64,
            input_bits,
            output_bits,
            start_level: Some(start_level),
            asid: None,
            vmid: Some(Vmid(0x30 + mode)),
            controls: stage2_controls,
            stage1_memory: vmsa_test_harness::Stage1MemoryControls::DEFAULT,
            regime: vmsa_test_harness::RegimeAttributes::Normal,
        };
        let mut combined =
            context.install_combined_owned(stage1_root, stage1_setup, stage2_root, stage2_setup)?;
        if combined.tlbi(
            vmsa_test_harness::TlbiScope::InnerShareable,
            vmsa_test_harness::CombinedTlbiOperation::Stage1(
                vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(VIRTUAL_ADDRESS),
            ),
        ) != Err(vmsa_test_harness::HarnessError::InvalidState)
        {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        combined.tlbi(
            vmsa_test_harness::TlbiScope::Local,
            vmsa_test_harness::CombinedTlbiOperation::Stage1(
                vmsa_test_harness::TlbiOperation::VirtualAddress(VIRTUAL_ADDRESS),
            ),
        )?;
        combined.tlbi(
            vmsa_test_harness::TlbiScope::InnerShareable,
            vmsa_test_harness::CombinedTlbiOperation::Stage1(
                vmsa_test_harness::TlbiOperation::Asid(Asid(0x40 + mode)),
            ),
        )?;
        combined.tlbi(
            vmsa_test_harness::TlbiScope::InnerShareable,
            vmsa_test_harness::CombinedTlbiOperation::Stage2(
                vmsa_test_harness::TlbiOperation::IntermediatePhysicalAddress(target_region),
            ),
        )?;
        combined.tlbi(
            vmsa_test_harness::TlbiScope::Local,
            vmsa_test_harness::CombinedTlbiOperation::Stage2(
                vmsa_test_harness::TlbiOperation::Vmid(Vmid(0x30 + mode)),
            ),
        )?;
        combined.tlbi(
            vmsa_test_harness::TlbiScope::InnerShareable,
            vmsa_test_harness::CombinedTlbiOperation::All,
        )?;
        let installed_stage1_output = combined
            .stage1_mut()?
            .inspect_for::<
                LowerRegime,
                aarch64_vmsa::descriptor::Vmsa64,
                aarch64_vmsa::address::Granule4KiB,
            >(VIRTUAL_ADDRESS)?
            .ok_or(vmsa_test_harness::HarnessError::InvalidState)?
            .output;
        if installed_stage1_output != target_ipa {
            return vmsa_test_harness::HarnessError::InvalidState.into();
        }
        if !omit_target {
            let semantic_config = aarch64_vmsa::attrs::LiveVmsaConfig {
                mair: 0x0000_ff44,
                mair2: None,
                stage1_permissions: None,
                stage2_permissions: None,
                stage2_memory_mode: aarch64_vmsa::attrs::Stage2MemoryMode::FwbDisabled,
                d128_stage1_alias: aarch64_vmsa::attrs::D128Stage1AliasKind::NonGlobal,
                shareability: aarch64_vmsa::attrs::Shareability::InnerShareable,
                output_pas: (),
            };
            let semantic = combined
                .stage2_mut()?
                .inspect_semantic_for::<
                    Stage2Regime,
                    aarch64_vmsa::descriptor::Vmsa64,
                    aarch64_vmsa::address::Granule4KiB,
                    aarch64_vmsa::attrs::VmsaAttributeCodec,
                    _,
                >(target_region, &semantic_config)?
                .ok_or(vmsa_test_harness::HarnessError::InvalidState)?;
            if semantic.permissions.data != aarch64_vmsa::attrs::DataAccess::ReadWrite
                || semantic.controls.shareability
                    != aarch64_vmsa::attrs::Shareability::InnerShareable
                || !semantic.controls.access_flag
            {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
        }
        let query = combined.translate(VIRTUAL_ADDRESS, TranslationQueryAccess::Read);
        if omit_target {
            match query {
                TranslationQueryResult::Fault { stage2: true, .. } => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
            match combined.read_u64(VIRTUAL_ADDRESS) {
                vmsa_test_harness::AccessResult::Fault(fault)
                    if fault.stage == vmsa_test_harness::FaultStage::Stage2 => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
        } else {
            match query {
                TranslationQueryResult::Success {
                    physical_address, ..
                } if physical_address == data_page.phys_addr() => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
            match combined.read_u64(VIRTUAL_ADDRESS) {
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
            let original_pair = match combined.read_pair_u64(VIRTUAL_ADDRESS) {
                vmsa_test_harness::AccessResult::CompletedPair { first, second } => (first, second),
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            };
            if !matches!(
                combined.read_u8(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value }
                    if value == DATA_VALUE & 0xff
            ) || !matches!(
                combined.read_u16(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value }
                    if value == DATA_VALUE & 0xffff
            ) || !matches!(
                combined.read_u32(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value }
                    if value == DATA_VALUE & 0xffff_ffff
            ) || !matches!(
                combined.write_release_u64(VIRTUAL_ADDRESS, DATA_VALUE),
                vmsa_test_harness::AccessResult::Completed { .. }
            ) || !matches!(
                combined.read_acquire_u64(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE
            ) || !matches!(
                combined.atomic_swap_u64(VIRTUAL_ADDRESS, DATA_VALUE + 1),
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE
            ) || !matches!(
                combined.exclusive_add_u64(VIRTUAL_ADDRESS, 1),
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE + 1
            ) || !matches!(
                combined.write_pair_u64(VIRTUAL_ADDRESS, original_pair.0, original_pair.1),
                vmsa_test_harness::AccessResult::CompletedPair { .. }
            ) || !matches!(
                combined.read_pair_u64(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::CompletedPair { first, second }
                    if first == original_pair.0 && second == original_pair.1
            ) {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
            match combined.execute(VIRTUAL_ADDRESS) {
                vmsa_test_harness::AccessResult::Fault(fault)
                    if fault.access == vmsa_test_harness::AccessKind::Execute => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
            combined.stage1_mut()?.protect_for::<
                LowerRegime,
                aarch64_vmsa::descriptor::Vmsa64,
                aarch64_vmsa::address::Granule4KiB,
            >(
                VIRTUAL_ADDRESS,
                MappingAttributes {
                    writable: false,
                    executable: false,
                    user_accessible: true,
                },
            )?;
            match combined.write_u64(VIRTUAL_ADDRESS, DATA_VALUE + 3) {
                vmsa_test_harness::AccessResult::Fault(fault)
                    if fault.stage == vmsa_test_harness::FaultStage::Stage1 => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
            combined.stage1_mut()?.protect_for::<
                LowerRegime,
                aarch64_vmsa::descriptor::Vmsa64,
                aarch64_vmsa::address::Granule4KiB,
            >(
                VIRTUAL_ADDRESS,
                MappingAttributes {
                    writable: true,
                    executable: false,
                    user_accessible: true,
                },
            )?;
            combined.stage2_mut()?.protect_for::<
                Stage2Regime,
                aarch64_vmsa::descriptor::Vmsa64,
                aarch64_vmsa::address::Granule4KiB,
            >(target_region, MappingAttributes::READ_ONLY)?;
            match combined.write_u64(VIRTUAL_ADDRESS, DATA_VALUE + 4) {
                vmsa_test_harness::AccessResult::Fault(fault)
                    if fault.stage == vmsa_test_harness::FaultStage::Stage2 => {}
                _ => return vmsa_test_harness::HarnessError::InvalidState.into(),
            }
            combined.stage2_mut()?.protect_for::<
                Stage2Regime,
                aarch64_vmsa::descriptor::Vmsa64,
                aarch64_vmsa::address::Granule4KiB,
            >(target_region, MappingAttributes::READ_WRITE)?;
            if !matches!(
                combined.read_u64(VIRTUAL_ADDRESS),
                vmsa_test_harness::AccessResult::Completed { value } if value == DATA_VALUE
            ) {
                return vmsa_test_harness::HarnessError::InvalidState.into();
            }
        }
        combined.restore()?;
    }
    TestResult::Pass
}
