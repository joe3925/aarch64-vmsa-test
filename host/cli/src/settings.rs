use std::time::Duration;

pub const CONTAINER_IMAGE: &str = "docker.io/shrinkwraptool/base-full@sha256:9edd12d9a811c439d69e256cef4cd9b2d07255eb337331276a50f077770bfff1";
pub const CACHE_VOLUME: &str = "aarch64-vmsa-fvp-cache";
pub const DEFAULT_VMSA_URL: &str = "https://github.com/joe3925/aarch64-vmsa";

pub const TF_A_REVISION: &str = "1d5aa939bc8d3d892e2ed9945fa50e36a1a924cc";
pub const TF_A_TESTS_REVISION: &str = "3b3d800133081b48482b1205a32671b82bc2b640";
pub const HAFNIUM_REVISION: &str = "ce12c6e53838f1cf07d50b616b72db57a81539a4";
pub const TF_RMM_REVISION: &str = "13a82ef5f3bbe4181c8c73a898b6ccdd61e12dae";

pub const BUILD_TIMEOUT: Duration = Duration::from_secs(300);
pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
pub const REALM_STAGE2_STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
pub const SUITE_TIMEOUT: Duration = Duration::from_secs(300);
pub const TEST_TIMEOUT: Duration = Duration::from_secs(15);
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
pub const RESULT_PREFIX: &str = "@@VMSA";
pub const PROTOCOL_VERSION: u32 = 1;
pub const PROTOCOL_LINE_LIMIT: usize = 512;
pub const PROCESS_LINE_LIMIT: usize = 64 * 1024;
pub const TEST_NAME_LIMIT: usize = 128;
pub const FILTER_LIMIT: usize = 128;
