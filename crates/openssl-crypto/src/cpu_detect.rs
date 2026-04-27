//! CPU capability detection for the OpenSSL Rust workspace.
//!
//! Detects hardware crypto acceleration features (AES-NI, SHA extensions, NEON,
//! AVX-512, etc.) at runtime. Replaces C `OPENSSL_cpuid_setup()` and per-platform
//! capability globals (`OPENSSL_ia32cap_P`, `OPENSSL_armcap_P`, etc.).
//!
//! # Architecture
//!
//! The C implementation is spread across seven platform-specific files:
//!
//! | C Source                  | Platform     | Rust Equivalent            |
//! |---------------------------|--------------|----------------------------|
//! | `crypto/cpuid.c`          | `x86/x86_64` | `detect_x86_features()`    |
//! | `crypto/armcap.c`         | ARM/AArch64  | `detect_arm_features()`    |
//! | `crypto/ppccap.c`         | `PowerPC64`  | Arch-only detection        |
//! | `crypto/riscvcap.c`       | RISC-V 64    | Arch-only detection        |
//! | `crypto/s390xcap.c`       | s390x        | Arch-only detection        |
//! | `crypto/sparcv9cap.c`     | SPARC v9     | Arch-only detection        |
//! | `crypto/loongarchcap.c`   | `LoongArch`  | Arch-only detection        |
//!
//! In C, each file populates a global capability variable (e.g.,
//! `OPENSSL_ia32cap_P[4]`, `OPENSSL_armcap_P`) during library initialization
//! via `OPENSSL_cpuid_setup()`. This Rust module replaces all seven files with
//! a unified, type-safe detection system using [`bitflags`] for feature sets
//! and [`once_cell::sync::Lazy`] for thread-safe singleton caching.
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** Returns typed `CpuCapabilities` struct, never sentinel integers.
//! - **R6 (Lossless Casts):** No bare `as` casts — all conversions use typed methods.
//! - **R8 (Zero Unsafe):** Detection uses safe `std::is_x86_feature_detected!()` and
//!   `std::arch::is_aarch64_feature_detected!()` macros — zero `unsafe` blocks.
//! - **R9 (Warning-Free):** All items documented; no `#[allow(unused)]`.
//! - **R10 (Wiring):** Reachable via `init::initialize()` → `cpu_detect::detect()`.
//!
//! # Usage
//!
//! ```rust,ignore
//! use openssl_crypto::cpu_detect;
//!
//! // One-time detection (cached automatically)
//! let caps = cpu_detect::capabilities();
//! println!("Architecture: {:?}", caps.arch);
//!
//! // Quick feature queries
//! if cpu_detect::has_aesni() {
//!     println!("AES-NI hardware acceleration available");
//! }
//! ```

use std::sync::Once;

use bitflags::bitflags;
use once_cell::sync::Lazy;

use openssl_common::error::CryptoError;

// =============================================================================
// X86Features — x86/x86_64 CPU Capability Flags
// =============================================================================

bitflags! {
    /// Hardware feature flags for x86 and x86_64 architectures.
    ///
    /// Replaces the C `OPENSSL_ia32cap_P[4]` capability array from
    /// `crypto/cpuid.c` (line 15). Each flag corresponds to a CPUID feature
    /// bit that OpenSSL checks for hardware-accelerated algorithm paths.
    ///
    /// The C implementation stores 128 bits of capability data across four
    /// `unsigned int` elements (`OPENSSL_ia32cap_P[0..3]`), populated by the
    /// `OPENSSL_ia32_cpuid()` assembly routine. This Rust type replaces that
    /// with a type-safe bitflags struct using safe `std::is_x86_feature_detected!()`
    /// queries.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use openssl_crypto::cpu_detect::X86Features;
    ///
    /// let features = X86Features::AESNI | X86Features::PCLMULQDQ;
    /// assert!(features.contains(X86Features::AESNI));
    /// assert_eq!(features.bits(), 0b_0000_0010_0010_0000);
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct X86Features: u64 {
        /// SSE2 instructions — baseline for x86_64.
        /// Required by most OpenSSL x86 assembly routines.
        const SSE2 = 1 << 0;

        /// SSE3 streaming SIMD extensions.
        const SSE3 = 1 << 1;

        /// Supplemental SSE3 (SSSE3) — byte shuffle, horizontal adds.
        const SSSE3 = 1 << 2;

        /// SSE4.1 — blend, extract, insert, rounding instructions.
        const SSE41 = 1 << 3;

        /// SSE4.2 — CRC32 instruction, string comparison.
        const SSE42 = 1 << 4;

        /// AES New Instructions (AES-NI) — hardware AES encryption/decryption.
        /// Provides 3–10x speedup over software AES. Critical for AES-GCM,
        /// AES-CBC, AES-CTR, AES-XTS, and AES key wrapping.
        const AESNI = 1 << 5;

        /// Advanced Vector Extensions — 256-bit floating-point SIMD.
        const AVX = 1 << 6;

        /// AVX2 — 256-bit integer SIMD operations.
        /// Enables wider parallel processing for ChaCha20, BigNum, and
        /// elliptic curve scalar multiplication.
        const AVX2 = 1 << 7;

        /// AVX-512 Foundation — 512-bit SIMD operations.
        /// When combined with VAES and VPCLMULQDQ, enables highly parallel
        /// AES-GCM processing on modern Intel/AMD processors.
        const AVX512F = 1 << 8;

        /// Carry-Less Multiplication Quadword — essential for efficient
        /// GCM (Galois Counter Mode) GHASH computation. Always checked
        /// alongside AES-NI for AES-GCM hardware acceleration.
        const PCLMULQDQ = 1 << 9;

        /// SHA Extensions (Intel SHA-NI) — hardware SHA-1 and SHA-256.
        /// Provides significant speedup for the most commonly used hash
        /// algorithms in TLS certificate verification and HMAC.
        const SHA = 1 << 10;

        /// Bit Manipulation Instruction Set 1 — ANDN, BEXTR, BLSI, BLSMSK, BLSR, TZCNT.
        const BMI1 = 1 << 11;

        /// Bit Manipulation Instruction Set 2 — BZHI, MULX, PDEP, PEXT, RORX, SARX, SHLX, SHRX.
        /// MULX is particularly useful for BigNum multiplication.
        const BMI2 = 1 << 12;

        /// Multi-Precision Add-Carry Extension — ADCX, ADOX instructions.
        /// Accelerates BigNum arithmetic (RSA, DH, DSA key operations) by
        /// providing two independent carry chains.
        const ADX = 1 << 13;

        /// Vector AES (AVX-512 VAES extension) — parallel AES on 512-bit vectors.
        /// Enables processing 4 AES blocks simultaneously in AES-GCM.
        const VAES = 1 << 14;

        /// Vector CLMUL (AVX-512 VPCLMULQDQ extension) — parallel carry-less
        /// multiply on 512-bit vectors for accelerated GCM GHASH.
        const VPCLMULQDQ = 1 << 15;
    }
}

// =============================================================================
// ArmFeatures — ARM/AArch64 CPU Capability Flags
// =============================================================================

bitflags! {
    /// Hardware feature flags for ARM and AArch64 architectures.
    ///
    /// Replaces the C `OPENSSL_armcap_P` capability variable from
    /// `crypto/armcap.c` (line 31) and the `ARMV7_*` / `ARMV8_*` constants
    /// defined in `arm_arch.h`. The C implementation uses a single `unsigned int`
    /// bitmask populated via `getauxval(AT_HWCAP)` on Linux, `sysctl` on macOS,
    /// or SIGILL-based probing as a fallback.
    ///
    /// This Rust type replaces that pattern with safe
    /// `std::arch::is_aarch64_feature_detected!()` queries on AArch64 targets.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use openssl_crypto::cpu_detect::ArmFeatures;
    ///
    /// let features = ArmFeatures::NEON | ArmFeatures::AES | ArmFeatures::SHA256;
    /// assert!(features.contains(ArmFeatures::NEON));
    /// assert!(features.intersects(ArmFeatures::AES | ArmFeatures::PMULL));
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ArmFeatures: u64 {
        /// NEON/ASIMD SIMD engine (`ARMV7_NEON` in C).
        /// Guaranteed present on all AArch64 processors.
        const NEON = 1 << 0;

        /// AES crypto extension (`ARMV8_AES` in C).
        /// Provides hardware-accelerated AES, analogous to x86 AES-NI.
        const AES = 1 << 1;

        /// SHA-1 crypto extension (`ARMV8_SHA1` in C).
        /// Hardware-accelerated SHA-1 hashing.
        const SHA1 = 1 << 2;

        /// SHA-256 crypto extension (`ARMV8_SHA256` in C).
        /// Hardware-accelerated SHA-256 hashing.
        const SHA256 = 1 << 3;

        /// Polynomial Multiply Long (`ARMV8_PMULL` in C).
        /// Enables efficient GCM GHASH computation on ARM, analogous
        /// to x86 PCLMULQDQ.
        const PMULL = 1 << 4;

        /// SHA-512 crypto extension (`ARMV8_SHA512` in C).
        /// Hardware-accelerated SHA-512 hashing, available on ARMv8.2+.
        const SHA512 = 1 << 5;

        /// Scalable Vector Extension (SVE).
        /// Variable-length SIMD (128–2048 bits) for data-parallel crypto.
        const SVE = 1 << 6;

        /// Scalable Vector Extension 2 (SVE2).
        /// Enhanced SVE with additional crypto-relevant instructions.
        const SVE2 = 1 << 7;
    }
}

// =============================================================================
// CpuArch — Architecture Identifier Enum
// =============================================================================

/// Identifies the CPU architecture of the current platform.
///
/// Determined at compile time via `cfg!(target_arch = ...)`. Replaces the
/// implicit platform detection in C via `#if defined(__x86_64)` / `#if defined(__aarch64__)`
/// preprocessor guards scattered across the seven platform-specific detection files.
///
/// # Architecture Mapping
///
/// | C Guard                     | Rust Variant       |
/// |-----------------------------|--------------------|
/// | `defined(__x86_64)`         | [`CpuArch::X86_64`]   |
/// | `defined(__i386)`           | [`CpuArch::X86`]      |
/// | `defined(__aarch64__)`      | [`CpuArch::Aarch64`]  |
/// | `defined(__arm__)`          | [`CpuArch::Arm`]      |
/// | `defined(_ARCH_PPC64)`      | [`CpuArch::PowerPc64`]|
/// | `defined(__s390x__)`        | [`CpuArch::S390x`]    |
/// | `defined(__riscv) && 64`    | [`CpuArch::RiscV64`]  |
/// | (none matched)              | [`CpuArch::Unknown`]  |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuArch {
    /// 64-bit x86 (AMD64 / Intel 64).
    X86_64,
    /// 32-bit x86 (IA-32).
    X86,
    /// 64-bit ARM (`AArch64` / ARM64).
    Aarch64,
    /// 32-bit ARM (`ARMv7` and below).
    Arm,
    /// 64-bit `PowerPC` (ppc64le / ppc64).
    PowerPc64,
    /// IBM System/390x mainframe.
    S390x,
    /// 64-bit RISC-V.
    RiscV64,
    /// Unknown or unsupported architecture.
    Unknown,
}

impl std::fmt::Display for CpuArch {
    /// Formats the architecture as a human-readable string suitable for
    /// logging and diagnostics output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::X86_64 => "x86_64",
            Self::X86 => "x86",
            Self::Aarch64 => "aarch64",
            Self::Arm => "arm",
            Self::PowerPc64 => "powerpc64",
            Self::S390x => "s390x",
            Self::RiscV64 => "riscv64",
            Self::Unknown => "unknown",
        };
        f.write_str(name)
    }
}

// =============================================================================
// CpuCapabilities — Runtime Capability Snapshot
// =============================================================================

/// Runtime snapshot of detected CPU capabilities.
///
/// Captures the current platform's architecture and available hardware
/// acceleration features in a single immutable struct. Initialized once via
/// [`detect()`] and cached in a [`Lazy`] static for the process lifetime.
///
/// Replaces the C global variables:
/// - `OPENSSL_ia32cap_P[4]` (`x86/x86_64` — `crypto/cpuid.c` line 15)
/// - `OPENSSL_armcap_P` (ARM/AArch64 — `crypto/armcap.c` line 31)
/// - `OPENSSL_ppccap_P` (`PowerPC` — `crypto/ppccap.c` line 33)
/// - `OPENSSL_riscvcap_P` (RISC-V — `crypto/riscvcap.c` line 35)
/// - `OPENSSL_s390xcap_P` (s390x — `crypto/s390xcap.c`)
/// - `OPENSSL_sparcv9cap_P` (SPARC — `crypto/sparcv9cap.c` line 24)
/// - `OPENSSL_loongarch_hwcap_P` (`LoongArch` — `crypto/loongarchcap.c` line 12)
///
/// # Thread Safety
///
/// This struct is `Send + Sync` and immutable after initialization. Access is
/// via the [`capabilities()`] function backed by a [`Lazy`] static, which
/// guarantees thread-safe one-time initialization.
///
/// # Example
///
/// ```rust,ignore
/// use openssl_crypto::cpu_detect;
///
/// let caps = cpu_detect::capabilities();
/// match caps.arch {
///     cpu_detect::CpuArch::X86_64 => {
///         if caps.x86.contains(cpu_detect::X86Features::AESNI) {
///             println!("AES-NI hardware acceleration available");
///         }
///     }
///     cpu_detect::CpuArch::Aarch64 => {
///         if caps.arm.contains(cpu_detect::ArmFeatures::AES) {
///             println!("ARM AES crypto extension available");
///         }
///     }
///     _ => println!("No specialized detection for this platform"),
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CpuCapabilities {
    /// The detected CPU architecture (compile-time determination).
    pub arch: CpuArch,
    /// Detected `x86/x86_64` hardware features.
    /// Empty (`X86Features::empty()`) on non-x86 platforms.
    pub x86: X86Features,
    /// Detected ARM/AArch64 hardware features.
    /// Empty (`ArmFeatures::empty()`) on non-ARM platforms.
    pub arm: ArmFeatures,
}

// =============================================================================
// Initialization Infrastructure
// =============================================================================

/// One-time initialization guard for logging, matching the C `static int trigger`
/// pattern in `OPENSSL_cpuid_setup()` (`crypto/cpuid.c`, line 96).
///
/// Ensures that detection-result logging happens exactly once, even if
/// [`detect()`] is called multiple times (e.g., both directly and via
/// the [`CAPABILITIES`] lazy static).
static INIT: Once = Once::new();

/// Lazily-initialized global CPU capabilities singleton.
///
/// Replaces the C global variables (`OPENSSL_ia32cap_P`, `OPENSSL_armcap_P`,
/// etc.) with a thread-safe, lazily-initialized Rust struct. First access
/// triggers [`detect()`], and the result is cached for the process lifetime.
///
/// # Ordering Guarantee
///
/// `Lazy::new()` uses internal synchronization equivalent to
/// `std::sync::Once`, ensuring that concurrent first-access from multiple
/// threads results in exactly one call to `detect()`.
static CAPABILITIES: Lazy<CpuCapabilities> = Lazy::new(detect);

// =============================================================================
// Platform-Specific Detection — Internal Functions
// =============================================================================

/// Detects `x86/x86_64` hardware features using the safe `is_x86_feature_detected!` macro.
///
/// On `x86/x86_64` platforms, queries CPUID leaf data for each hardware
/// acceleration feature relevant to OpenSSL's algorithm implementations.
/// On non-x86 platforms, this function is compiled to return an empty feature set.
///
/// # C Correspondence
///
/// Replaces `OPENSSL_cpuid_setup()` from `crypto/cpuid.c` (lines 94–171),
/// which populates `OPENSSL_ia32cap_P[0..3]` via the `OPENSSL_ia32_cpuid()`
/// assembly routine and optional `OPENSSL_ia32cap` environment variable overrides.
///
/// The environment variable override mechanism is intentionally NOT replicated
/// in Rust — runtime capability masking should use feature flags instead.
fn detect_x86_features() -> X86Features {
    let mut features = X86Features::empty();

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        // SSE family — baseline for modern x86 (x86_64 guarantees SSE2)
        if std::is_x86_feature_detected!("sse2") {
            features |= X86Features::SSE2;
        }
        if std::is_x86_feature_detected!("sse3") {
            features |= X86Features::SSE3;
        }
        if std::is_x86_feature_detected!("ssse3") {
            features |= X86Features::SSSE3;
        }
        if std::is_x86_feature_detected!("sse4.1") {
            features |= X86Features::SSE41;
        }
        if std::is_x86_feature_detected!("sse4.2") {
            features |= X86Features::SSE42;
        }

        // AES-NI: Hardware AES acceleration
        // C: checked as bit 25 of CPUID leaf 1 ECX (crypto/cpuid.c IA32CAP)
        if std::is_x86_feature_detected!("aes") {
            features |= X86Features::AESNI;
        }

        // PCLMULQDQ: Carry-less multiply for GCM mode
        // C: checked as bit 1 of CPUID leaf 1 ECX
        if std::is_x86_feature_detected!("pclmulqdq") {
            features |= X86Features::PCLMULQDQ;
        }

        // AVX family — wider SIMD for parallel crypto
        if std::is_x86_feature_detected!("avx") {
            features |= X86Features::AVX;
        }
        if std::is_x86_feature_detected!("avx2") {
            features |= X86Features::AVX2;
        }
        if std::is_x86_feature_detected!("avx512f") {
            features |= X86Features::AVX512F;
        }

        // SHA Extensions: Hardware SHA-1/SHA-256 (Intel SHA-NI)
        // C: checked in OPENSSL_ia32cap_P extended feature bits
        if std::is_x86_feature_detected!("sha") {
            features |= X86Features::SHA;
        }

        // BMI1/2: Bit manipulation for bignum and constant-time operations
        if std::is_x86_feature_detected!("bmi1") {
            features |= X86Features::BMI1;
        }
        if std::is_x86_feature_detected!("bmi2") {
            features |= X86Features::BMI2;
        }

        // ADX: Multi-precision add-carry for accelerated bignum
        // (rsaz-avx2, x86_64-mont5 assembly routines in C)
        if std::is_x86_feature_detected!("adx") {
            features |= X86Features::ADX;
        }

        // VAES: AVX-512 Vector AES — parallel AES on 512-bit vectors
        if std::is_x86_feature_detected!("vaes") {
            features |= X86Features::VAES;
        }

        // VPCLMULQDQ: AVX-512 Vector CLMUL — parallel GCM GHASH
        if std::is_x86_feature_detected!("vpclmulqdq") {
            features |= X86Features::VPCLMULQDQ;
        }
    }

    features
}

/// Detects ARM/AArch64 hardware features using the safe
/// `is_aarch64_feature_detected!` macro.
///
/// On `AArch64` platforms, queries hardware capability registers for crypto
/// extensions via the OS-provided HWCAP mechanism. On non-ARM platforms,
/// this function is compiled to return an empty feature set.
///
/// # C Correspondence
///
/// Replaces `OPENSSL_cpuid_setup()` from `crypto/armcap.c` which populates
/// `OPENSSL_armcap_P` via three detection methods (in order of preference):
/// 1. `sysctl` queries on macOS (`crypto/armcap.c` lines 226–236)
/// 2. `getauxval(AT_HWCAP)` on Linux/Android (`crypto/armcap.c` lines 72–148)
/// 3. SIGILL-based probing as fallback (`crypto/armcap.c` lines 193–250)
///
/// The Rust `std::arch::is_aarch64_feature_detected!()` macro abstracts all
/// three methods via the standard library, providing a single safe API.
///
/// # Feature Mapping
///
/// | C Constant   | HWCAP Bit              | Rust Detection String |
/// |-------------|------------------------|-----------------------|
/// | `ARMV7_NEON`| `OSSL_HWCAP_NEON`      | `"neon"`             |
/// | `ARMV8_AES` | `OSSL_HWCAP_CE_AES`   | `"aes"`              |
/// | `ARMV8_SHA1`| (implied by SHA2)      | `"sha2"`             |
/// | `ARMV8_SHA256`| `OSSL_HWCAP_CE_SHA256`| `"sha2"`            |
/// | `ARMV8_PMULL`| `OSSL_HWCAP_CE_PMULL` | `"pmull"`            |
/// | `ARMV8_SHA512`| `OSSL_HWCAP_CE_SHA512`| `"sha3"`            |
/// | SVE         | `OSSL_HWCAP_SVE`       | `"sve"`              |
/// | SVE2        | `OSSL_HWCAP2_SVE2`     | `"sve2"`             |
fn detect_arm_features() -> ArmFeatures {
    // On AArch64 targets, probe each hardware crypto extension using the safe
    // std::arch::is_aarch64_feature_detected!() macro. On all other targets,
    // the cfg block is compiled away and an empty feature set is returned.
    #[cfg(target_arch = "aarch64")]
    {
        let mut features = ArmFeatures::empty();

        // NEON/ASIMD is architecturally guaranteed on all AArch64 processors
        // C: OPENSSL_armcap_P |= ARMV7_NEON (armcap.c line 42)
        if std::arch::is_aarch64_feature_detected!("neon") {
            features |= ArmFeatures::NEON;
        }

        // AES crypto extension (ARMV8_AES)
        // C: OPENSSL_armcap_P |= ARMV8_AES (armcap.c line 46)
        if std::arch::is_aarch64_feature_detected!("aes") {
            features |= ArmFeatures::AES;
        }

        // SHA-2 extension covers both SHA-1 and SHA-256 on AArch64.
        // In the ARM architecture, FEAT_SHA1 and FEAT_SHA256 are architecturally
        // paired — processors implementing one always implement both.
        // C: OPENSSL_armcap_P |= ARMV8_SHA1 | ARMV8_SHA256 (armcap.c lines 48-49)
        if std::arch::is_aarch64_feature_detected!("sha2") {
            features |= ArmFeatures::SHA1;
            features |= ArmFeatures::SHA256;
        }

        // PMULL: Polynomial Multiply Long for GCM GHASH
        // C: OPENSSL_armcap_P |= ARMV8_PMULL (armcap.c line 47)
        if std::arch::is_aarch64_feature_detected!("pmull") {
            features |= ArmFeatures::PMULL;
        }

        // SHA-512 extension (part of FEAT_SHA3/FEAT_SHA512, available ARMv8.2+)
        // C: armcap.c line 143: OSSL_HWCAP_CE_SHA512 check
        if std::arch::is_aarch64_feature_detected!("sha3") {
            features |= ArmFeatures::SHA512;
        }

        // SVE: Scalable Vector Extension
        // C: armcap.c line 144: OSSL_HWCAP_SVE check
        if std::arch::is_aarch64_feature_detected!("sve") {
            features |= ArmFeatures::SVE;
        }

        // SVE2: Scalable Vector Extension 2
        // C: armcap.c line 147: OSSL_HWCAP2_SVE2 check
        if std::arch::is_aarch64_feature_detected!("sve2") {
            features |= ArmFeatures::SVE2;
        }

        features
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        ArmFeatures::empty()
    }
}

/// Determines the CPU architecture at compile time.
///
/// Uses `cfg!()` macros to identify the target architecture, mapping to the
/// corresponding [`CpuArch`] variant. This replaces the scattered
/// `#if defined(__x86_64)` / `#if defined(__aarch64__)` preprocessor guards
/// across the seven C platform-detection files.
///
/// # Compile-Time Resolution
///
/// Architecture detection is resolved at compile time via `cfg!()`, which
/// evaluates to a boolean constant. The optimizer eliminates all dead branches,
/// producing a single `return` instruction.
fn detect_arch() -> CpuArch {
    if cfg!(target_arch = "x86_64") {
        CpuArch::X86_64
    } else if cfg!(target_arch = "x86") {
        CpuArch::X86
    } else if cfg!(target_arch = "aarch64") {
        CpuArch::Aarch64
    } else if cfg!(target_arch = "arm") {
        CpuArch::Arm
    } else if cfg!(target_arch = "powerpc64") {
        CpuArch::PowerPc64
    } else if cfg!(target_arch = "s390x") {
        CpuArch::S390x
    } else if cfg!(target_arch = "riscv64") {
        CpuArch::RiscV64
    } else {
        CpuArch::Unknown
    }
}

// =============================================================================
// Public API — Detection and Initialization
// =============================================================================

/// Performs one-time CPU capability detection and returns the results.
///
/// This function:
/// 1. Identifies the CPU architecture via compile-time `cfg!()` checks
/// 2. Probes platform-specific hardware features using safe stdlib macros
/// 3. Logs the detection results via `tracing` (observability requirement)
/// 4. Returns a [`CpuCapabilities`] struct capturing all detected features
///
/// Replaces the C `OPENSSL_cpuid_setup()` function, which is called once
/// during library initialization from `crypto/init.c` via the
/// `OPENSSL_INIT_BASE_ONLY` stage.
///
/// # Safety
///
/// This function uses exclusively safe Rust APIs:
/// - `std::is_x86_feature_detected!()` — safe CPUID queries (stable since Rust 1.27)
/// - `std::arch::is_aarch64_feature_detected!()` — safe HWCAP queries (stable since Rust 1.61)
///
/// No `unsafe` blocks per Rule R8.
///
/// # Examples
///
/// ```rust,ignore
/// use openssl_crypto::cpu_detect;
///
/// let caps = cpu_detect::detect();
/// println!("Architecture: {:?}", caps.arch);
/// println!("x86 features: {:?}", caps.x86);
/// println!("ARM features: {:?}", caps.arm);
/// ```
pub fn detect() -> CpuCapabilities {
    let arch = detect_arch();
    let x86 = detect_x86_features();
    let arm = detect_arm_features();

    // Log detection results exactly once (observability requirement per AAP §0.8.5).
    // The INIT guard ensures this logging happens only on the first call, even if
    // detect() is invoked multiple times (e.g., both directly and via the Lazy static).
    INIT.call_once(|| {
        tracing::info!(
            arch = %arch,
            x86_feature_bits = x86.bits(),
            arm_feature_bits = arm.bits(),
            "CPU capability detection completed"
        );
    });

    CpuCapabilities { arch, x86, arm }
}

/// Returns a reference to the lazily-initialized global CPU capabilities.
///
/// The first call triggers [`detect()`]; subsequent calls return the cached
/// result with zero overhead. Thread-safe via [`once_cell::sync::Lazy`].
///
/// Replaces the C pattern of reading global variables
/// (`OPENSSL_ia32cap_P`, `OPENSSL_armcap_P`, etc.) that are populated by
/// `OPENSSL_cpuid_setup()` during library initialization.
///
/// # Examples
///
/// ```rust,ignore
/// use openssl_crypto::cpu_detect;
///
/// let caps = cpu_detect::capabilities();
/// if caps.arch == cpu_detect::CpuArch::X86_64 {
///     println!("Running on x86_64 with {} features detected",
///              caps.x86.bits().count_ones());
/// }
/// ```
pub fn capabilities() -> &'static CpuCapabilities {
    &CAPABILITIES
}

// =============================================================================
// Public API — Quick Feature Query Functions
// =============================================================================
//
// These convenience functions replace direct reads of the C globals like
// `if (OPENSSL_ia32cap_P[1] & (1<<(57-32)))` scattered throughout the
// OpenSSL C codebase. Each function calls capabilities() to access the
// cached singleton and checks the relevant feature flag.

/// Returns `true` if the CPU supports AES-NI (`x86/x86_64` only).
///
/// AES-NI provides hardware-accelerated AES encryption/decryption, typically
/// delivering 3–10x speedup over software implementations. In the C codebase,
/// this is checked via `OPENSSL_ia32cap_P` bit tests in cipher dispatch
/// (e.g., `crypto/evp/e_aes.c`, `providers/implementations/ciphers/cipher_aes.c`).
///
/// Returns `false` on non-x86 architectures.
///
/// # Examples
///
/// ```rust,ignore
/// if openssl_crypto::cpu_detect::has_aesni() {
///     println!("AES-NI available — using hardware AES path");
/// }
/// ```
pub fn has_aesni() -> bool {
    capabilities().x86.contains(X86Features::AESNI)
}

/// Returns `true` if the CPU supports SHA Extensions (`x86/x86_64` only).
///
/// SHA Extensions (Intel SHA-NI) provide hardware-accelerated SHA-1 and
/// SHA-256 hashing. Checked in the C codebase via `OPENSSL_ia32cap_P`
/// extended feature flags (`crypto/sha/sha_local.h`).
///
/// Returns `false` on non-x86 architectures.
pub fn has_sha_extensions() -> bool {
    capabilities().x86.contains(X86Features::SHA)
}

/// Returns `true` if the CPU supports AVX2 (`x86/x86_64` only).
///
/// AVX2 provides 256-bit integer SIMD operations, enabling wider parallel
/// processing for cryptographic operations like ChaCha20-Poly1305 and
/// `BigNum` multiplication (used in RSA, DH, ECDSA).
///
/// Returns `false` on non-x86 architectures.
pub fn has_avx2() -> bool {
    capabilities().x86.contains(X86Features::AVX2)
}

/// Returns `true` if the CPU supports AVX-512 Foundation (`x86/x86_64` only).
///
/// AVX-512F provides 512-bit SIMD operations. Combined with [`has_aesni()`]
/// and VAES/VPCLMULQDQ extensions, it enables highly parallel AES-GCM
/// processing on modern Intel/AMD server processors.
///
/// Returns `false` on non-x86 architectures.
pub fn has_avx512() -> bool {
    capabilities().x86.contains(X86Features::AVX512F)
}

/// Returns `true` if the CPU supports PCLMULQDQ (`x86/x86_64` only).
///
/// PCLMULQDQ (Carry-Less Multiplication) is essential for efficient GCM
/// (Galois Counter Mode) GHASH computation. Always checked alongside AES-NI
/// for complete AES-GCM hardware acceleration in the C codebase.
///
/// Returns `false` on non-x86 architectures.
pub fn has_pclmulqdq() -> bool {
    capabilities().x86.contains(X86Features::PCLMULQDQ)
}

/// Returns `true` if the CPU supports NEON/ASIMD (ARM/AArch64 only).
///
/// NEON provides 128-bit SIMD operations on ARM processors. On `AArch64`,
/// NEON is architecturally guaranteed (always present). Checked in the C
/// codebase via `OPENSSL_armcap_P & ARMV7_NEON` (`crypto/armcap.c`).
///
/// Returns `false` on non-ARM architectures.
pub fn has_neon() -> bool {
    capabilities().arm.contains(ArmFeatures::NEON)
}

/// Returns `true` if the CPU supports the ARM AES crypto extension (`AArch64` only).
///
/// The `ARMv8` AES extension provides hardware-accelerated AES operations,
/// analogous to x86 AES-NI. Checked in the C codebase via
/// `OPENSSL_armcap_P & ARMV8_AES` (`crypto/armcap.c` line 46).
///
/// Returns `false` on non-ARM architectures.
pub fn has_arm_aes() -> bool {
    capabilities().arm.contains(ArmFeatures::AES)
}

// =============================================================================
// Validation Helper
// =============================================================================

/// Validates that CPU detection completed successfully for the current platform.
///
/// Returns `Ok(())` if the architecture was recognized (i.e., not
/// [`CpuArch::Unknown`]), or a [`CryptoError`] if the platform could not be
/// identified. This function is called during library initialization to report
/// unrecognized platforms via the structured error system.
///
/// On known architectures (even those without detailed feature detection like
/// `PowerPC` or s390x), detection is considered successful — the architecture
/// is recognized even if no hardware acceleration flags are set.
///
/// # Errors
///
/// Returns [`CryptoError::Common`] wrapping
/// [`CommonError::Unsupported`](openssl_common::error::CommonError::Unsupported)
/// if the CPU architecture is [`CpuArch::Unknown`].
///
/// # Examples
///
/// ```rust,ignore
/// use openssl_crypto::cpu_detect;
///
/// let caps = cpu_detect::detect();
/// match cpu_detect::validate_detection(&caps) {
///     Ok(()) => println!("CPU detection successful: {}", caps.arch),
///     Err(e) => eprintln!("CPU detection warning: {}", e),
/// }
/// ```
pub fn validate_detection(caps: &CpuCapabilities) -> Result<(), CryptoError> {
    match caps.arch {
        CpuArch::Unknown => Err(CryptoError::Common(
            openssl_common::error::CommonError::Unsupported(
                "unknown CPU architecture — hardware acceleration features unavailable".to_string(),
            ),
        )),
        _ => Ok(()),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that detect() returns a valid CpuCapabilities struct.
    #[test]
    fn test_detect_returns_valid_capabilities() {
        let caps = detect();
        // On x86_64 CI, we should detect X86_64 architecture
        #[cfg(target_arch = "x86_64")]
        assert_eq!(caps.arch, CpuArch::X86_64);

        #[cfg(target_arch = "aarch64")]
        assert_eq!(caps.arch, CpuArch::Aarch64);
    }

    /// Verify that capabilities() returns a cached singleton reference.
    #[test]
    fn test_capabilities_returns_static_ref() {
        let caps1 = capabilities();
        let caps2 = capabilities();
        // Both should point to the same static allocation
        assert_eq!(
            caps1 as *const CpuCapabilities,
            caps2 as *const CpuCapabilities
        );
    }

    /// Verify that X86Features bitflags work correctly.
    #[test]
    fn test_x86_features_bitflags() {
        let empty = X86Features::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.bits(), 0);

        let aes_gcm = X86Features::AESNI | X86Features::PCLMULQDQ;
        assert!(aes_gcm.contains(X86Features::AESNI));
        assert!(aes_gcm.contains(X86Features::PCLMULQDQ));
        assert!(!aes_gcm.contains(X86Features::AVX2));
        assert!(aes_gcm.intersects(X86Features::AESNI));

        // Verify all 16 flags have unique bit positions
        let all = X86Features::all();
        assert_eq!(all.bits().count_ones(), 16);
    }

    /// Verify that ArmFeatures bitflags work correctly.
    #[test]
    fn test_arm_features_bitflags() {
        let empty = ArmFeatures::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.bits(), 0);

        let crypto = ArmFeatures::AES | ArmFeatures::SHA256 | ArmFeatures::PMULL;
        assert!(crypto.contains(ArmFeatures::AES));
        assert!(crypto.contains(ArmFeatures::SHA256));
        assert!(!crypto.contains(ArmFeatures::SVE));
        assert!(crypto.intersects(ArmFeatures::AES | ArmFeatures::NEON));

        // Verify all 8 flags have unique bit positions
        let all = ArmFeatures::all();
        assert_eq!(all.bits().count_ones(), 8);
    }

    /// Verify CpuArch Display formatting.
    #[test]
    fn test_cpu_arch_display() {
        assert_eq!(format!("{}", CpuArch::X86_64), "x86_64");
        assert_eq!(format!("{}", CpuArch::Aarch64), "aarch64");
        assert_eq!(format!("{}", CpuArch::PowerPc64), "powerpc64");
        assert_eq!(format!("{}", CpuArch::S390x), "s390x");
        assert_eq!(format!("{}", CpuArch::RiscV64), "riscv64");
        assert_eq!(format!("{}", CpuArch::Unknown), "unknown");
    }

    /// Verify CpuArch equality and clone.
    #[test]
    fn test_cpu_arch_clone_eq() {
        let arch = CpuArch::X86_64;
        let cloned = arch;
        assert_eq!(arch, cloned);
        assert_ne!(arch, CpuArch::Aarch64);
    }

    /// Verify that detect_arch() returns a known architecture on CI.
    #[test]
    fn test_detect_arch_known() {
        let arch = detect_arch();
        // On any standard CI platform, the architecture should be known
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "powerpc64",
            target_arch = "s390x",
            target_arch = "riscv64"
        ))]
        assert_ne!(arch, CpuArch::Unknown);

        // Suppress unused variable warning on unsupported architectures
        let _ = arch;
    }

    /// Verify x86 feature detection produces consistent results.
    #[test]
    fn test_x86_feature_detection_consistent() {
        let features1 = detect_x86_features();
        let features2 = detect_x86_features();
        // Feature detection should be deterministic
        assert_eq!(features1, features2);
    }

    /// Verify ARM feature detection produces consistent results.
    #[test]
    fn test_arm_feature_detection_consistent() {
        let features1 = detect_arm_features();
        let features2 = detect_arm_features();
        // Feature detection should be deterministic
        assert_eq!(features1, features2);
    }

    /// On x86_64, SSE2 is architecturally guaranteed.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_x86_64_has_sse2() {
        let features = detect_x86_features();
        assert!(
            features.contains(X86Features::SSE2),
            "SSE2 must be present on x86_64"
        );
    }

    /// Verify has_aesni() is consistent with direct feature check.
    #[test]
    fn test_has_aesni_consistency() {
        let direct = capabilities().x86.contains(X86Features::AESNI);
        assert_eq!(has_aesni(), direct);
    }

    /// Verify has_sha_extensions() is consistent with direct feature check.
    #[test]
    fn test_has_sha_extensions_consistency() {
        let direct = capabilities().x86.contains(X86Features::SHA);
        assert_eq!(has_sha_extensions(), direct);
    }

    /// Verify has_avx2() is consistent with direct feature check.
    #[test]
    fn test_has_avx2_consistency() {
        let direct = capabilities().x86.contains(X86Features::AVX2);
        assert_eq!(has_avx2(), direct);
    }

    /// Verify has_avx512() is consistent with direct feature check.
    #[test]
    fn test_has_avx512_consistency() {
        let direct = capabilities().x86.contains(X86Features::AVX512F);
        assert_eq!(has_avx512(), direct);
    }

    /// Verify has_pclmulqdq() is consistent with direct feature check.
    #[test]
    fn test_has_pclmulqdq_consistency() {
        let direct = capabilities().x86.contains(X86Features::PCLMULQDQ);
        assert_eq!(has_pclmulqdq(), direct);
    }

    /// Verify has_neon() is consistent with direct feature check.
    #[test]
    fn test_has_neon_consistency() {
        let direct = capabilities().arm.contains(ArmFeatures::NEON);
        assert_eq!(has_neon(), direct);
    }

    /// Verify has_arm_aes() is consistent with direct feature check.
    #[test]
    fn test_has_arm_aes_consistency() {
        let direct = capabilities().arm.contains(ArmFeatures::AES);
        assert_eq!(has_arm_aes(), direct);
    }

    /// Verify that validate_detection succeeds for known architectures.
    #[test]
    fn test_validate_detection_known_arch() {
        let caps = CpuCapabilities {
            arch: CpuArch::X86_64,
            x86: X86Features::empty(),
            arm: ArmFeatures::empty(),
        };
        assert!(validate_detection(&caps).is_ok());
    }

    /// Verify that validate_detection returns error for unknown architecture.
    #[test]
    fn test_validate_detection_unknown_arch() {
        let caps = CpuCapabilities {
            arch: CpuArch::Unknown,
            x86: X86Features::empty(),
            arm: ArmFeatures::empty(),
        };
        let result = validate_detection(&caps);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_string = format!("{}", err);
        assert!(
            err_string.contains("unknown CPU architecture"),
            "Error message should mention unknown architecture, got: {}",
            err_string
        );
    }

    /// Verify CpuCapabilities clone.
    #[test]
    fn test_cpu_capabilities_clone() {
        let caps = detect();
        let cloned = caps.clone();
        assert_eq!(caps.arch, cloned.arch);
        assert_eq!(caps.x86, cloned.x86);
        assert_eq!(caps.arm, cloned.arm);
    }

    /// Verify CpuCapabilities debug formatting.
    #[test]
    fn test_cpu_capabilities_debug() {
        let caps = detect();
        let debug_str = format!("{:?}", caps);
        assert!(debug_str.contains("CpuCapabilities"));
        assert!(debug_str.contains("arch"));
    }

    /// Verify that on non-x86 platforms, x86 features are empty.
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    #[test]
    fn test_non_x86_has_empty_x86_features() {
        let caps = detect();
        assert!(caps.x86.is_empty());
    }

    /// Verify that on non-ARM platforms, ARM features are empty.
    #[cfg(not(target_arch = "aarch64"))]
    #[test]
    fn test_non_arm_has_empty_arm_features() {
        let caps = detect();
        assert!(caps.arm.is_empty());
    }
}
