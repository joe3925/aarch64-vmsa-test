use aarch64_vmsa::address::TranslationGranule;
use aarch64_vmsa::attrs::{AttributeCodec, LiveVmsaConfig};
use aarch64_vmsa::config::format::{BigEndian, LittleEndian, NativeEndian, Vmsa64, Vmsa64Lpa2, Vmsa128};
use aarch64_vmsa::config::granule::{Granule4KiB, Granule16KiB, Granule64KiB};
use aarch64_vmsa::config::regime::{smmu_v2, smmu_v3};
use aarch64_vmsa::regime::TranslationRegime;

fn require_codec<F, R, G, C>()
where
    R: TranslationRegime,
    G: TranslationGranule,
    F: AttributeCodec<R, G, C>,
{
}

fn main() {
    // Positive control: the SMMUv3 VMSA-128 stage-1 semantic codec exists.
    require_codec::<Vmsa128, smmu_v3::NonSecureStreamStage1, Granule4KiB, LiveVmsaConfig>();

    macro_rules! granules {
        ($format:ty, $regime:ty) => {
            require_codec::<$format, $regime, Granule4KiB, LiveVmsaConfig>();
            require_codec::<$format, $regime, Granule16KiB, LiveVmsaConfig>();
            require_codec::<$format, $regime, Granule64KiB, LiveVmsaConfig>();
        };
    }
    macro_rules! endians {
        ($format:ident, $regime:ty) => {
            granules!($format<NativeEndian>, $regime);
            granules!($format<LittleEndian>, $regime);
            granules!($format<BigEndian>, $regime);
        };
    }
    macro_rules! v2_regimes {
        ($format:ident) => {
            endians!($format, smmu_v2::NonSecureStreamStage1);
            endians!($format, smmu_v2::NonSecurePrivilegedStreamStage1);
            endians!($format, smmu_v2::SecureStreamStage1);
            endians!($format, smmu_v2::SecurePrivilegedStreamStage1);
        };
    }
    macro_rules! v3_regimes {
        ($format:ident) => {
            endians!($format, smmu_v3::NonSecureStreamStage1);
            endians!($format, smmu_v3::NonSecurePrivilegedStreamStage1);
            endians!($format, smmu_v3::SecureStreamStage1);
            endians!($format, smmu_v3::SecurePrivilegedStreamStage1);
            endians!($format, smmu_v3::RealmStreamStage1);
            endians!($format, smmu_v3::RealmPrivilegedStreamStage1);
        };
    }

    v2_regimes!(Vmsa64);
    v3_regimes!(Vmsa64);
    v3_regimes!(Vmsa64Lpa2);
}
