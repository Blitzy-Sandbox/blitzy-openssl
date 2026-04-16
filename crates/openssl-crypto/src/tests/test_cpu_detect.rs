//! Integration tests for CPU capability detection.
//!
//! These tests validate the public API surface of the `cpu_detect` module,
//! covering runtime CPU capability detection, cached singleton access,
//! architecture identification, platform-specific feature queries, and
//! convenience query functions.
//!
//! Reference: `test/rdcpu_sanitytest.c` — C-side CPU random-number sanity
//! checks that conditionally test x86 (rdrand/rdseed) or aarch64 (rndr/rndrrs)
//! based on runtime CPU capability bits.
//!
//! Key rules:
//! - **R5:** Detection returns typed values (`CpuCapabilities`, `CpuArch`,
//!   bitflag types) — no sentinel integers.
//! - **R8:** ZERO `unsafe` — detection uses safe `is_x86_feature_detected!` and
//!   `is_aarch64_feature_detected!` macros under the hood.
//! - **R10:** CPU detection is reachable via `init → cpu_detect::detect()`.

use crate::cpu_detect::*;

// =============================================================================
// Phase 2: Detection Tests (reference: test/rdcpu_sanitytest.c)
// =============================================================================

/// Validates that [`detect()`] completes successfully without panicking.
///
/// This is the most basic sanity check — the CPU detection routine must
/// always complete regardless of the underlying hardware. Analogous to
/// the C `rdcpu_sanitytest.c` basic setup that calls `OPENSSL_cpuid_setup()`.
#[test]
fn test_cpu_detect_runs_without_panic() {
    // detect() must always succeed and return a well-formed CpuCapabilities.
    let caps: CpuCapabilities = detect();

    // The arch field must always be populated with a valid variant.
    // Access each field to confirm the struct is well-formed.
    let arch: CpuArch = caps.arch;
    let x86: X86Features = caps.x86;
    let arm: ArmFeatures = caps.arm;

    // Bind all values to verify they are accessible without panic.
    let _ = (arch, x86, arm);
}

/// Validates that [`capabilities()`] returns the same cached result on repeated calls.
///
/// The `capabilities()` function uses a `Lazy` static to cache the detection
/// result. Calling it multiple times must yield pointer-equal references to
/// the same `CpuCapabilities` instance, guaranteeing zero redundant detection.
#[test]
fn test_cpu_capabilities_cached() {
    let first: &CpuCapabilities = capabilities();
    let second: &CpuCapabilities = capabilities();

    // Both references must point to the same static allocation.
    assert!(
        std::ptr::eq(first, second),
        "capabilities() must return the same cached reference on every call"
    );

    // Verify logical equality of all fields across calls.
    assert_eq!(
        first.arch, second.arch,
        "Cached arch must be consistent across calls"
    );

    // Call a third time to reinforce the caching guarantee.
    let third: &CpuCapabilities = capabilities();
    assert!(
        std::ptr::eq(first, third),
        "capabilities() must be stable across any number of calls"
    );
}

/// Validates that the detected CPU architecture matches the compile-time target.
///
/// Uses Rust's `cfg!()` macro to determine the expected architecture at compile
/// time and asserts that [`detect()`] agrees. This prevents misidentification
/// on the running platform — the Rust equivalent of checking `OPENSSL_ia32cap_P`
/// (x86) or `OPENSSL_armcap_P` (ARM) against known platform constraints.
#[test]
fn test_cpu_arch_detection() {
    let caps: CpuCapabilities = detect();

    if cfg!(target_arch = "x86_64") {
        assert_eq!(
            caps.arch,
            CpuArch::X86_64,
            "On x86_64 targets, detected arch must be CpuArch::X86_64"
        );
    } else if cfg!(target_arch = "aarch64") {
        assert_eq!(
            caps.arch,
            CpuArch::Aarch64,
            "On aarch64 targets, detected arch must be CpuArch::Aarch64"
        );
    }

    // On any architecture, verify that the CpuArch Display implementation
    // produces a non-empty human-readable string.
    let arch_display = format!("{}", caps.arch);
    assert!(
        !arch_display.is_empty(),
        "CpuArch Display must produce a non-empty string"
    );
}

// =============================================================================
// Phase 3: Platform-Specific Feature Tests
// =============================================================================

/// On `x86_64`, SSE2 is a baseline requirement of the AMD64 specification.
///
/// Every conforming `x86_64` processor must support SSE2. This test validates
/// that the detection logic correctly identifies SSE2 as present, mirroring
/// the C assumption that `OPENSSL_ia32cap_P` always has the SSE2 bit set
/// on 64-bit x86.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_x86_sse2_detected() {
    let caps: &CpuCapabilities = capabilities();

    // SSE2 is mandatory on all x86_64 processors — guaranteed by the ISA.
    assert!(
        caps.x86.contains(X86Features::SSE2),
        "SSE2 must be detected on x86_64 — it is part of the AMD64 baseline ISA"
    );

    // x86 features must not be empty since at least SSE2 is present.
    assert_ne!(
        caps.x86,
        X86Features::empty(),
        "x86 features must not be empty on x86_64"
    );
}

/// Validates that [`X86Features`] bitflags operations work correctly.
///
/// Exercises `contains()`, `empty()`, bitwise OR composition, and verifies
/// that named flag constants are properly defined as distinct non-zero bits.
/// This ensures the `bitflags!` macro expansion is sound and all required
/// feature constants are accessible.
#[cfg(target_arch = "x86_64")]
#[test]
fn test_x86_features_bitflags() {
    let caps: &CpuCapabilities = capabilities();
    let features: X86Features = caps.x86;

    // On x86_64, features MUST NOT be empty (SSE2 baseline guaranteed).
    assert_ne!(
        features,
        X86Features::empty(),
        "x86_64 must have at least SSE2, so features cannot be empty"
    );

    // `contains()` with SSE2 must succeed — baseline guarantee.
    assert!(
        features.contains(X86Features::SSE2),
        "contains(SSE2) must return true on x86_64"
    );

    // Verify that `empty()` yields a zero-valued bitflag.
    let empty = X86Features::empty();
    assert!(
        !empty.contains(X86Features::SSE2),
        "empty() must not contain any flags"
    );

    // Test bitwise OR composition — combine multiple flags.
    let combined = X86Features::AESNI | X86Features::AVX2;
    // `contains()` on the combined set checks if BOTH bits are set.
    // The actual result depends on hardware, but the operation must not panic.
    let _has_both: bool = features.contains(combined);

    // Verify that each individual flag constant is non-zero and distinct.
    assert_ne!(
        X86Features::SSE2,
        X86Features::empty(),
        "SSE2 flag must be non-zero"
    );
    assert_ne!(
        X86Features::AESNI,
        X86Features::empty(),
        "AESNI flag must be non-zero"
    );
    assert_ne!(
        X86Features::AVX2,
        X86Features::empty(),
        "AVX2 flag must be non-zero"
    );
    assert_ne!(
        X86Features::AVX512F,
        X86Features::empty(),
        "AVX512F flag must be non-zero"
    );
    assert_ne!(
        X86Features::PCLMULQDQ,
        X86Features::empty(),
        "PCLMULQDQ flag must be non-zero"
    );
    assert_ne!(
        X86Features::SHA,
        X86Features::empty(),
        "SHA flag must be non-zero"
    );

    // Verify that flag constants are pairwise distinct (each occupies a unique bit).
    assert_ne!(
        X86Features::AESNI,
        X86Features::AVX2,
        "AESNI and AVX2 must be distinct"
    );
    assert_ne!(
        X86Features::AVX2,
        X86Features::AVX512F,
        "AVX2 and AVX512F must be distinct"
    );
    assert_ne!(
        X86Features::SHA,
        X86Features::PCLMULQDQ,
        "SHA and PCLMULQDQ must be distinct"
    );
    assert_ne!(
        X86Features::SSE2,
        X86Features::AESNI,
        "SSE2 and AESNI must be distinct"
    );
}

/// On `aarch64`, NEON (Advanced SIMD) is a mandatory extension of `ARMv8-A`.
///
/// Every conforming `aarch64` processor must support NEON. This test validates
/// that the detection correctly identifies NEON as present, mirroring the C
/// assumption that `OPENSSL_armcap_P` always has `ARMV7_NEON` set on 64-bit ARM.
#[cfg(target_arch = "aarch64")]
#[test]
fn test_arm_neon_detected() {
    let caps: &CpuCapabilities = capabilities();

    // NEON is mandatory in the ARMv8-A specification — it is always present.
    assert!(
        caps.arm.contains(ArmFeatures::NEON),
        "NEON must be detected on aarch64 — it is part of the ARMv8-A baseline"
    );

    // ARM features must not be empty since at least NEON is present.
    assert_ne!(
        caps.arm,
        ArmFeatures::empty(),
        "ARM features must not be empty on aarch64"
    );
}

/// Validates that [`ArmFeatures`] bitflags operations work correctly.
///
/// Exercises `contains()`, `empty()`, bitwise OR composition, and verifies
/// that named flag constants are properly defined as distinct non-zero bits.
#[cfg(target_arch = "aarch64")]
#[test]
fn test_arm_features_bitflags() {
    let caps: &CpuCapabilities = capabilities();
    let features: ArmFeatures = caps.arm;

    // On aarch64, features MUST NOT be empty (NEON baseline guaranteed).
    assert_ne!(
        features,
        ArmFeatures::empty(),
        "aarch64 must have at least NEON, so features cannot be empty"
    );

    // `contains()` with NEON must succeed — baseline guarantee.
    assert!(
        features.contains(ArmFeatures::NEON),
        "contains(NEON) must return true on aarch64"
    );

    // Verify that `empty()` yields a zero-valued bitflag.
    let empty = ArmFeatures::empty();
    assert!(
        !empty.contains(ArmFeatures::NEON),
        "empty() must not contain any flags"
    );

    // Test bitwise OR composition with NEON and AES flags.
    let combined = ArmFeatures::NEON | ArmFeatures::AES;
    // The actual result depends on hardware, but the operation must not panic.
    let _has_both: bool = features.contains(combined);

    // Verify individual flags are non-zero.
    assert_ne!(
        ArmFeatures::NEON,
        ArmFeatures::empty(),
        "NEON flag must be non-zero"
    );
    assert_ne!(
        ArmFeatures::AES,
        ArmFeatures::empty(),
        "AES flag must be non-zero"
    );

    // Verify flags are pairwise distinct.
    assert_ne!(
        ArmFeatures::NEON,
        ArmFeatures::AES,
        "NEON and AES must be distinct"
    );
}

// =============================================================================
// Phase 4: Query Function Tests
// =============================================================================

/// Validates that all convenience query functions return `bool` without panicking.
///
/// Each `has_*()` function wraps [`capabilities()`] and checks a specific feature
/// flag. The exact return value depends on hardware, but the functions must never
/// panic. On `x86_64`, we additionally cross-check the convenience results against
/// direct bitflag queries for consistency.
#[test]
fn test_has_functions_return_bool() {
    // Exercise every convenience function — must not panic on any platform.
    let aesni: bool = has_aesni();
    let sha: bool = has_sha_extensions();
    let avx2: bool = has_avx2();
    let avx512: bool = has_avx512();
    let pclmulqdq: bool = has_pclmulqdq();
    let neon: bool = has_neon();
    let arm_aes: bool = has_arm_aes();

    // On x86_64, cross-check convenience functions against direct bitflag queries.
    if cfg!(target_arch = "x86_64") {
        let caps = capabilities();
        assert_eq!(
            aesni,
            caps.x86.contains(X86Features::AESNI),
            "has_aesni() must match caps.x86.contains(AESNI)"
        );
        assert_eq!(
            sha,
            caps.x86.contains(X86Features::SHA),
            "has_sha_extensions() must match caps.x86.contains(SHA)"
        );
        assert_eq!(
            avx2,
            caps.x86.contains(X86Features::AVX2),
            "has_avx2() must match caps.x86.contains(AVX2)"
        );
        assert_eq!(
            avx512,
            caps.x86.contains(X86Features::AVX512F),
            "has_avx512() must match caps.x86.contains(AVX512F)"
        );
        assert_eq!(
            pclmulqdq,
            caps.x86.contains(X86Features::PCLMULQDQ),
            "has_pclmulqdq() must match caps.x86.contains(PCLMULQDQ)"
        );
    }

    // On aarch64, cross-check ARM convenience functions.
    if cfg!(target_arch = "aarch64") {
        let caps = capabilities();
        assert_eq!(
            neon,
            caps.arm.contains(ArmFeatures::NEON),
            "has_neon() must match caps.arm.contains(NEON)"
        );
        assert_eq!(
            arm_aes,
            caps.arm.contains(ArmFeatures::AES),
            "has_arm_aes() must match caps.arm.contains(AES)"
        );
    }

    // Bind all results to prevent unused-variable warnings while
    // preserving the explicit bool type annotations above.
    let _ = (aesni, sha, avx2, avx512, pclmulqdq, neon, arm_aes);
}

/// Validates that [`CpuCapabilities`] implements [`Debug`].
///
/// The `Debug` trait is required for diagnostic output, error messages, and
/// `assert_eq!` macro support. The formatted output must be non-empty and
/// must include the struct name and field names.
#[test]
fn test_capabilities_struct_debug() {
    let caps: CpuCapabilities = detect();
    let debug_str = format!("{caps:?}");

    // The debug output must be non-empty.
    assert!(
        !debug_str.is_empty(),
        "Debug output for CpuCapabilities must not be empty"
    );

    // The debug output should contain the struct name (derived Debug includes it).
    assert!(
        debug_str.contains("CpuCapabilities"),
        "Debug output must contain 'CpuCapabilities', got: {debug_str}",
    );

    // The debug output should contain the arch field name.
    assert!(
        debug_str.contains("arch"),
        "Debug output must contain 'arch' field name, got: {debug_str}",
    );

    // Verify Clone works (CpuCapabilities derives Clone).
    let cloned = caps.clone();
    let cloned_debug = format!("{cloned:?}");
    assert_eq!(
        debug_str, cloned_debug,
        "Cloned CpuCapabilities must have identical Debug output"
    );
}
