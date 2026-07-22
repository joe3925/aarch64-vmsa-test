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
const NORMAL_SECURE_REALM: SecurityEnvironments = NORMAL_SECURE.union(SecurityEnvironments::REALM);
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

macro_rules! define_catalog {
    ($($variant:ident, $name:literal, $builder:ident($($argument:expr),*), $normal:tt, $secure:tt, $realm:tt, $rec:tt, $root:tt;)*) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u16)]
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

const CATALOG_NAME_SLOTS: usize = 4096;

const fn catalog_name_hash(name: &str) -> usize {
    let bytes = name.as_bytes();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    hash as usize
}

const _: () = {
    assert!(TEST_CATALOG.len() < CATALOG_NAME_SLOTS);
    let mut occupied = [usize::MAX; CATALOG_NAME_SLOTS];
    let mut index = 0;
    while index < TEST_CATALOG.len() {
        let name = TEST_CATALOG[index].name;
        assert!(valid_catalog_name(name));

        let mut slot = catalog_name_hash(name) & (CATALOG_NAME_SLOTS - 1);
        let mut probes = 0;
        while occupied[slot] != usize::MAX {
            assert!(!same_name(name, TEST_CATALOG[occupied[slot]].name));
            slot = (slot + 1) & (CATALOG_NAME_SLOTS - 1);
            probes += 1;
            assert!(probes < CATALOG_NAME_SLOTS);
        }
        occupied[slot] = index;
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
