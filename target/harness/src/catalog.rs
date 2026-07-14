use crate::Requirements;
use crate::matrix::{
    BootProfile, BootProfiles, DescriptorFormats, ExecutionContexts, FirmwareRequirement,
    HarnessCapabilities, IsolationRequirement, MatrixRequirements, PeRequirement,
    PhysicalAddressSpaces, SecurityEnvironment, SecurityEnvironments, TranslationGranules,
    TranslationOwnerships,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    pub id: LogicalTest,
    pub name: &'static str,
    pub architecture: MatrixRequirements,
    pub model: Requirements,
}

impl CatalogEntry {
    pub const fn applies_to(self, environment: SecurityEnvironment, profile: BootProfile) -> bool {
        self.architecture.environments.contains(environment)
            && self.architecture.boot_profiles.contains(profile)
    }
}

const ALL_ENVIRONMENTS: SecurityEnvironments = SecurityEnvironments::ALL;
const NORMAL: SecurityEnvironments = SecurityEnvironments::NORMAL;
const NORMAL_SECURE: SecurityEnvironments =
    SecurityEnvironments::NORMAL.union(SecurityEnvironments::SECURE);
const NORMAL_ROOT: SecurityEnvironments =
    SecurityEnvironments::NORMAL.union(SecurityEnvironments::ROOT);
const NORMAL_SECURE_REALM_ROOT: SecurityEnvironments = ALL_ENVIRONMENTS;
const NON_REC_PROFILES: BootProfiles =
    BootProfiles::ALL.difference(BootProfiles::one(BootProfile::RealmRecStage2));

const fn matrix(environments: SecurityEnvironments) -> MatrixRequirements {
    MatrixRequirements {
        environments,
        boot_profiles: BootProfiles::ALL,
        ownerships: TranslationOwnerships::ALL,
        contexts: ExecutionContexts::ALL,
        formats: DescriptorFormats::ALL,
        granules: TranslationGranules::ALL,
        capabilities: HarnessCapabilities::NONE,
        address_spaces: PhysicalAddressSpaces::ALL,
        pe: PeRequirement::PrimaryOnly,
        firmware: FirmwareRequirement::None,
        isolation: IsolationRequirement::Sequential,
        expects_model_termination: false,
    }
}

const fn entry(
    id: LogicalTest,
    name: &'static str,
    environments: SecurityEnvironments,
    model: Requirements,
) -> CatalogEntry {
    CatalogEntry {
        id,
        name,
        architecture: matrix(environments),
        model,
    }
}

const fn profile_entry(
    id: LogicalTest,
    name: &'static str,
    environments: SecurityEnvironments,
    profiles: BootProfiles,
    model: Requirements,
) -> CatalogEntry {
    let mut entry = entry(id, name, environments, model);
    entry.architecture.boot_profiles = profiles;
    entry
}

const fn isolated_profile_entry(
    id: LogicalTest,
    name: &'static str,
    environments: SecurityEnvironments,
    profiles: BootProfiles,
    isolation: IsolationRequirement,
    expects_model_termination: bool,
    model: Requirements,
) -> CatalogEntry {
    let mut entry = profile_entry(id, name, environments, profiles, model);
    entry.architecture.isolation = isolation;
    entry.architecture.expects_model_termination = expects_model_termination;
    entry
}

const fn capability_entry(
    id: LogicalTest,
    name: &'static str,
    environments: SecurityEnvironments,
    capability: crate::HarnessCapability,
    model: Requirements,
) -> CatalogEntry {
    let mut entry = entry(id, name, environments, model);
    entry.architecture.capabilities = HarnessCapabilities::one(capability);
    entry
}

macro_rules! define_catalog {
    ($($variant:ident, $name:literal, $builder:ident($($argument:expr),*), $normal:tt, $secure:tt, $realm:tt, $rec:tt, $root:tt;)*) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u8)]
        pub enum LogicalTest {
            $($variant,)*
        }

        pub static TEST_CATALOG: &[CatalogEntry] = &[
            $($builder(LogicalTest::$variant, $name, $($argument),*),)*
        ];
    };
}

crate::for_each_registered_test!(define_catalog);

const CATALOG_NAME_LIMIT: usize = 128;

const fn valid_catalog_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > CATALOG_NAME_LIMIT {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if !byte.is_ascii_alphanumeric() && byte != b'.' && byte != b'-' && byte != b'_' {
            return false;
        }
        index += 1;
    }
    true
}

const fn same_name(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

const _: () = {
    let mut index = 0;
    while index < TEST_CATALOG.len() {
        assert!(valid_catalog_name(TEST_CATALOG[index].name));
        let mut other = index + 1;
        while other < TEST_CATALOG.len() {
            assert!(TEST_CATALOG[index].id as u8 != TEST_CATALOG[other].id as u8);
            assert!(!same_name(
                TEST_CATALOG[index].name,
                TEST_CATALOG[other].name
            ));
            other += 1;
        }
        index += 1;
    }
};

pub fn tests_for(
    environment: SecurityEnvironment,
    profile: BootProfile,
) -> impl Iterator<Item = &'static CatalogEntry> {
    TEST_CATALOG
        .iter()
        .filter(move |entry| entry.applies_to(environment, profile))
}
