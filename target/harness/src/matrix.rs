use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SecurityEnvironment {
    Normal,
    Secure,
    Realm,
    Root,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityEnvironments(u8);

impl SecurityEnvironments {
    pub const NONE: Self = Self(0);
    pub const NORMAL: Self = Self::one(SecurityEnvironment::Normal);
    pub const SECURE: Self = Self::one(SecurityEnvironment::Secure);
    pub const REALM: Self = Self::one(SecurityEnvironment::Realm);
    pub const ROOT: Self = Self::one(SecurityEnvironment::Root);
    pub const ALL: Self = Self(0b1111);

    pub const fn one(environment: SecurityEnvironment) -> Self {
        Self(1 << environment as u8)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, environment: SecurityEnvironment) -> bool {
        self.0 & (1 << environment as u8) != 0
    }
}

macro_rules! typed_set {
    ($set:ident, $item:ident, $repr:ty) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $set($repr);

        impl $set {
            pub const NONE: Self = Self(0);

            pub const fn one(item: $item) -> Self {
                Self(1 << item as u8)
            }

            pub const fn union(self, other: Self) -> Self {
                Self(self.0 | other.0)
            }

            pub const fn difference(self, other: Self) -> Self {
                Self(self.0 & !other.0)
            }

            pub const fn contains(self, item: $item) -> bool {
                self.0 & (1 << item as u8) != 0
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BootProfile {
    NsEl2,
    SecureEl2,
    RealmEl2,
    RealmRecStage2,
    RootEl3,
}
typed_set!(BootProfiles, BootProfile, u8);

impl BootProfiles {
    pub const ALL: Self = Self((1 << 5) - 1);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TranslationOwnership {
    CurrentStage1,
    LowerStage1,
    El2Stage2,
    CombinedStage1Stage2,
    RecRealmStage2,
    RootStage1,
}
typed_set!(TranslationOwnerships, TranslationOwnership, u8);

impl TranslationOwnerships {
    pub const ALL: Self = Self((1 << 6) - 1);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExecutionContext {
    CurrentEl,
    El1,
    El0UnderEl1,
    El0UnderEl2,
    RealmRec,
    SecondaryPe,
}
typed_set!(ExecutionContexts, ExecutionContext, u8);

impl ExecutionContexts {
    pub const ALL: Self = Self((1 << 6) - 1);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DescriptorFormat {
    Vmsa64,
    Lpa2,
    D128,
}
typed_set!(DescriptorFormats, DescriptorFormat, u8);

impl DescriptorFormats {
    pub const ALL: Self = Self((1 << 3) - 1);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TranslationGranule {
    Size4KiB,
    Size16KiB,
    Size64KiB,
}
typed_set!(TranslationGranules, TranslationGranule, u8);

impl TranslationGranules {
    pub const ALL: Self = Self((1 << 3) - 1);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PhysicalAddressSpace {
    NonSecure,
    Secure,
    Realm,
    Root,
    FirmwareShared,
    DelegatedRealm,
}
typed_set!(PhysicalAddressSpaces, PhysicalAddressSpace, u8);

impl PhysicalAddressSpaces {
    pub const ALL: Self = Self((1 << 6) - 1);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HarnessCapability {
    CreateRoot,
    MapPage,
    MapBlock,
    MapRange,
    CreateIntermediateTables,
    Remap,
    Protect,
    Unmap,
    Translate,
    InspectWalk,
    InspectDescriptor,
    BreakBeforeMake,
    InstallTranslation,
    MutateInstalledTranslation,
    RestoreTranslation,
    ReadWriteWidths,
    PairAccess,
    OrderedAccess,
    AtomicAccess,
    IndirectExecution,
    GeneratedExecution,
    AtPar,
    Asid,
    Vmid,
    AddressWidths,
    StartingLookupLevel,
    Tcr,
    Tcr2,
    Ttbr64,
    Ttbr128,
    Mair,
    Mair2,
    HardwareAccessFlag,
    HardwareDirtyState,
    PermissionIndirection,
    PermissionOverlay,
    Stage2MemoryControls,
    Shareability,
    Cacheability,
    NormalizedFault,
    GuardedExpectedFault,
    UnexpectedException,
    TypedTlbi,
    CacheMaintenance,
    TransitionSandbox,
    CurrentEl,
    El1,
    El0UnderEl1,
    El0UnderEl2,
    RealmRec,
    SecondaryPe,
    MemoryScope,
    PasOwnership,
    RealmLifecycle,
    FailureInjection,
    AbiValidation,
    AdapterStateMachine,
    EmergencyRestoration,
    BootIsolation,
    ProcessCleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HarnessCapabilities {
    low: u64,
    high: u64,
}

impl HarnessCapabilities {
    pub const NONE: Self = Self { low: 0, high: 0 };

    pub const fn one(capability: HarnessCapability) -> Self {
        let bit = capability as u8;
        if bit < 64 {
            Self {
                low: 1 << bit,
                high: 0,
            }
        } else {
            Self {
                low: 0,
                high: 1 << (bit - 64),
            }
        }
    }

    pub const fn union(self, other: Self) -> Self {
        Self {
            low: self.low | other.low,
            high: self.high | other.high,
        }
    }

    pub const fn contains(self, capability: HarnessCapability) -> bool {
        let bit = capability as u8;
        if bit < 64 {
            self.low & (1 << bit) != 0
        } else {
            self.high & (1 << (bit - 64)) != 0
        }
    }

    pub const fn is_subset_of(self, available: Self) -> bool {
        self.low & !available.low == 0 && self.high & !available.high == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeRequirement {
    PrimaryOnly,
    SecondaryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareRequirement {
    None,
    TfATests,
    Hafnium,
    TfRmm,
    TrustedRealmPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationRequirement {
    Sequential,
    SeparateBoot,
    DestructiveBoot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootGeometry {
    pub environment: SecurityEnvironment,
    pub owner: TranslationOwnership,
    pub format: DescriptorFormat,
    pub granule: TranslationGranule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatrixRequirements {
    pub environments: SecurityEnvironments,
    pub boot_profiles: BootProfiles,
    pub ownerships: TranslationOwnerships,
    pub contexts: ExecutionContexts,
    pub formats: DescriptorFormats,
    pub granules: TranslationGranules,
    pub capabilities: HarnessCapabilities,
    pub address_spaces: PhysicalAddressSpaces,
    pub pe: PeRequirement,
    pub firmware: FirmwareRequirement,
    pub isolation: IsolationRequirement,
    pub expects_model_termination: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Applicability {
    Applicable,
    Isolated,
    Destructive,
    Inapplicable,
    Unsupported,
    AdapterMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatrixSelection {
    pub environment: SecurityEnvironment,
    pub boot_profile: BootProfile,
    pub ownership: TranslationOwnership,
    pub context: ExecutionContext,
    pub format: DescriptorFormat,
    pub granule: TranslationGranule,
}

impl MatrixRequirements {
    pub const fn classify(
        self,
        selection: MatrixSelection,
        adapter_capabilities: HarnessCapabilities,
        architecture_supported: bool,
    ) -> Applicability {
        if !self.environments.contains(selection.environment)
            || !self.boot_profiles.contains(selection.boot_profile)
            || !self.ownerships.contains(selection.ownership)
            || !self.contexts.contains(selection.context)
            || !self.formats.contains(selection.format)
            || !self.granules.contains(selection.granule)
        {
            Applicability::Inapplicable
        } else if !architecture_supported {
            Applicability::Unsupported
        } else if !self.capabilities.is_subset_of(adapter_capabilities) {
            Applicability::AdapterMissing
        } else {
            if self.expects_model_termination {
                return Applicability::Destructive;
            }
            match self.isolation {
                IsolationRequirement::Sequential => Applicability::Applicable,
                IsolationRequirement::SeparateBoot => Applicability::Isolated,
                IsolationRequirement::DestructiveBoot => Applicability::Destructive,
            }
        }
    }

    pub const fn cases(self, logical_name: &'static str) -> MatrixCases {
        MatrixCases {
            logical_name,
            requirements: self,
            index: 0,
        }
    }
}

pub struct MatrixCases {
    logical_name: &'static str,
    requirements: MatrixRequirements,
    index: usize,
}

impl Iterator for MatrixCases {
    type Item = MatrixCaseIdentity<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        const CASE_COUNT: usize = 4 * 5 * 6 * 6 * 3 * 3;
        while self.index < CASE_COUNT {
            let mut index = self.index;
            self.index += 1;
            let granule = GRANULES[index % GRANULES.len()];
            index /= GRANULES.len();
            let format = FORMATS[index % FORMATS.len()];
            index /= FORMATS.len();
            let context = CONTEXTS[index % CONTEXTS.len()];
            index /= CONTEXTS.len();
            let ownership = OWNERSHIPS[index % OWNERSHIPS.len()];
            index /= OWNERSHIPS.len();
            let boot_profile = BOOT_PROFILES[index % BOOT_PROFILES.len()];
            index /= BOOT_PROFILES.len();
            let environment = ENVIRONMENTS[index];
            let selection = MatrixSelection {
                environment,
                boot_profile,
                ownership,
                context,
                format,
                granule,
            };
            if self.requirements.environments.contains(environment)
                && self.requirements.boot_profiles.contains(boot_profile)
                && self.requirements.ownerships.contains(ownership)
                && self.requirements.contexts.contains(context)
                && self.requirements.formats.contains(format)
                && self.requirements.granules.contains(granule)
            {
                return Some(MatrixCaseIdentity {
                    logical_name: self.logical_name,
                    selection,
                });
            }
        }
        None
    }
}

const ENVIRONMENTS: [SecurityEnvironment; 4] = [
    SecurityEnvironment::Normal,
    SecurityEnvironment::Secure,
    SecurityEnvironment::Realm,
    SecurityEnvironment::Root,
];
const BOOT_PROFILES: [BootProfile; 5] = [
    BootProfile::NsEl2,
    BootProfile::SecureEl2,
    BootProfile::RealmEl2,
    BootProfile::RealmRecStage2,
    BootProfile::RootEl3,
];
const OWNERSHIPS: [TranslationOwnership; 6] = [
    TranslationOwnership::CurrentStage1,
    TranslationOwnership::LowerStage1,
    TranslationOwnership::El2Stage2,
    TranslationOwnership::CombinedStage1Stage2,
    TranslationOwnership::RecRealmStage2,
    TranslationOwnership::RootStage1,
];
const CONTEXTS: [ExecutionContext; 6] = [
    ExecutionContext::CurrentEl,
    ExecutionContext::El1,
    ExecutionContext::El0UnderEl1,
    ExecutionContext::El0UnderEl2,
    ExecutionContext::RealmRec,
    ExecutionContext::SecondaryPe,
];
const FORMATS: [DescriptorFormat; 3] = [
    DescriptorFormat::Vmsa64,
    DescriptorFormat::Lpa2,
    DescriptorFormat::D128,
];
const GRANULES: [TranslationGranule; 3] = [
    TranslationGranule::Size4KiB,
    TranslationGranule::Size16KiB,
    TranslationGranule::Size64KiB,
];

pub struct MatrixCaseIdentity<'a> {
    pub logical_name: &'a str,
    pub selection: MatrixSelection,
}

impl fmt::Display for MatrixCaseIdentity<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}/env={}/boot={}/owner={}/exec={}/format={}/granule={}",
            self.logical_name,
            environment_name(self.selection.environment),
            boot_profile_name(self.selection.boot_profile),
            ownership_name(self.selection.ownership),
            context_name(self.selection.context),
            format_name(self.selection.format),
            granule_name(self.selection.granule),
        )
    }
}

const fn boot_profile_name(value: BootProfile) -> &'static str {
    match value {
        BootProfile::NsEl2 => "ns-el2",
        BootProfile::SecureEl2 => "secure-el2",
        BootProfile::RealmEl2 => "realm-el2",
        BootProfile::RealmRecStage2 => "realm-rec-stage2",
        BootProfile::RootEl3 => "root-el3",
    }
}

const fn environment_name(value: SecurityEnvironment) -> &'static str {
    match value {
        SecurityEnvironment::Normal => "normal",
        SecurityEnvironment::Secure => "secure",
        SecurityEnvironment::Realm => "realm",
        SecurityEnvironment::Root => "root",
    }
}

const fn ownership_name(value: TranslationOwnership) -> &'static str {
    match value {
        TranslationOwnership::CurrentStage1 => "current-stage1",
        TranslationOwnership::LowerStage1 => "lower-stage1",
        TranslationOwnership::El2Stage2 => "el2-stage2",
        TranslationOwnership::CombinedStage1Stage2 => "combined",
        TranslationOwnership::RecRealmStage2 => "rec-stage2",
        TranslationOwnership::RootStage1 => "root-stage1",
    }
}

const fn context_name(value: ExecutionContext) -> &'static str {
    match value {
        ExecutionContext::CurrentEl => "current-el",
        ExecutionContext::El1 => "el1",
        ExecutionContext::El0UnderEl1 => "el0-el1",
        ExecutionContext::El0UnderEl2 => "el0-el2",
        ExecutionContext::RealmRec => "rec",
        ExecutionContext::SecondaryPe => "secondary-pe",
    }
}

const fn format_name(value: DescriptorFormat) -> &'static str {
    match value {
        DescriptorFormat::Vmsa64 => "vmsa64",
        DescriptorFormat::Lpa2 => "lpa2",
        DescriptorFormat::D128 => "d128",
    }
}

const fn granule_name(value: TranslationGranule) -> &'static str {
    match value {
        TranslationGranule::Size4KiB => "4k",
        TranslationGranule::Size16KiB => "16k",
        TranslationGranule::Size64KiB => "64k",
    }
}
