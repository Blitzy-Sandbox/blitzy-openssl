// Test modules legitimately use `.unwrap()` / `.expect()` and test-specific
// patterns that trigger pedantic clippy lints.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::approx_constant,
    clippy::bool_assert_comparison,
    clippy::match_same_arms,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::stable_sort_primitive
)]

//! Tests for the typed parameter system replacing `OSSL_PARAM` in openssl-common.
//!
//! This module comprehensively tests the [`crate::param`] module, verifying:
//!
//! - **[`ParamValue`]** variant construction and accessor extraction for all 8 variants.
//! - **[`ParamSet`]** get/set/contains/remove/keys/len/is_empty/iter/merge/duplicate.
//! - **[`ParamSet::get_typed`]** type-safe extraction with error reporting.
//! - **[`ParamBuilder`]** fluent builder API for constructing parameter sets.
//! - **[`FromParam`]** trait implementations for i32/u32/i64/u64/f64/String/Vec<u8>/bool.
//! - **[`from_text`]** text-to-ParamValue parsing (integer, float, hex, string).
//! - **Error types:** [`CommonError::ParamTypeMismatch`], [`CommonError::ParamNotFound`],
//!   [`CommonError::InvalidArgument`], [`CommonError::CastOverflow`].
//!
//! # Rules Enforced
//!
//! - **R5 (Nullability):** Tests verify `None`/`Err` for missing/invalid—never sentinels.
//! - **R6 (Lossless Casts):** Narrowing conversion `i64::MAX → i32` tested for failure.
//! - **R8 (Zero Unsafe):** Zero `unsafe` code in this module.
//! - **R9 (Warning-Free):** Compiles with `RUSTFLAGS="-D warnings"`.
//! - **R10 (Wiring):** Tests exercise the param module through its public API.
//!
//! # Source References
//!
//! - `crypto/params.c` — OSSL_PARAM get/set/locate equivalents
//! - `crypto/param_build.c` — OSSL_PARAM_BLD builder pattern
//! - `crypto/params_dup.c` — Parameter duplication
//! - `crypto/params_from_text.c` — Text-to-parameter parsing
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_literal_unwrap
)]

use crate::error::CommonError;
use crate::param::*;

// =============================================================================
// Phase 2: ParamValue Variant Construction and Extraction Tests
// =============================================================================
// Mirrors C `OSSL_PARAM_construct_*` and type tag extraction.

#[test]
fn param_value_int32() {
    let val = ParamValue::Int32(42);
    assert_eq!(val.as_i32(), Some(42));
    // Cross-type accessor returns None (Rule R5 — no sentinel)
    assert_eq!(val.as_u64(), None);
    assert_eq!(val.as_str(), None);
    assert_eq!(val.as_f64(), None);
    assert_eq!(val.as_bytes(), None);
    assert_eq!(val.as_bignum(), None);
}

#[test]
fn param_value_uint32() {
    let val = ParamValue::UInt32(100);
    assert_eq!(val.as_u32(), Some(100));
    // Cross-type returns None
    assert_eq!(val.as_i32(), None);
    assert_eq!(val.as_u64(), None);
}

#[test]
fn param_value_int64() {
    let val = ParamValue::Int64(-1);
    assert_eq!(val.as_i64(), Some(-1));
    assert_eq!(val.as_i32(), None);
    assert_eq!(val.as_u64(), None);
}

#[test]
fn param_value_uint64() {
    let val = ParamValue::UInt64(u64::MAX);
    assert_eq!(val.as_u64(), Some(u64::MAX));
    assert_eq!(val.as_u32(), None);
    assert_eq!(val.as_i64(), None);
}

#[test]
fn param_value_real() {
    let val = ParamValue::Real(3.14);
    assert_eq!(val.as_f64(), Some(3.14));
    assert_eq!(val.as_i32(), None);
    assert_eq!(val.as_str(), None);
}

#[test]
fn param_value_utf8_string() {
    let val = ParamValue::Utf8String("hello".into());
    assert_eq!(val.as_str(), Some("hello"));
    assert_eq!(val.as_i32(), None);
    assert_eq!(val.as_bytes(), None);
}

#[test]
fn param_value_octet_string() {
    let val = ParamValue::OctetString(vec![1, 2, 3]);
    assert_eq!(val.as_bytes(), Some(&[1u8, 2, 3][..]));
    assert_eq!(val.as_str(), None);
    assert_eq!(val.as_bignum(), None);
}

#[test]
fn param_value_bignum() {
    let val = ParamValue::BigNum(vec![0xFF, 0xFE]);
    assert_eq!(val.as_bignum(), Some(&[0xFFu8, 0xFE][..]));
    assert_eq!(val.as_bytes(), None);
    assert_eq!(val.as_i64(), None);
}

#[test]
fn param_value_type_mismatch() {
    // Int32 asking for string → None (Rule R5, never sentinel)
    assert_eq!(ParamValue::Int32(42).as_str(), None);
    // Utf8String asking for int → None
    assert_eq!(ParamValue::Utf8String("x".into()).as_i32(), None);
    // Real asking for bytes → None
    assert_eq!(ParamValue::Real(1.0).as_bytes(), None);
    // OctetString asking for f64 → None
    assert_eq!(ParamValue::OctetString(vec![1]).as_f64(), None);
    // BigNum asking for u32 → None
    assert_eq!(ParamValue::BigNum(vec![1]).as_u32(), None);
}

#[test]
fn param_value_type_name() {
    // Verify param_type_name() returns the correct human-readable name for each variant.
    assert_eq!(ParamValue::Int32(0).param_type_name(), "Int32");
    assert_eq!(ParamValue::UInt32(0).param_type_name(), "UInt32");
    assert_eq!(ParamValue::Int64(0).param_type_name(), "Int64");
    assert_eq!(ParamValue::UInt64(0).param_type_name(), "UInt64");
    assert_eq!(ParamValue::Real(0.0).param_type_name(), "Real");
    assert_eq!(
        ParamValue::Utf8String(String::new()).param_type_name(),
        "Utf8String"
    );
    assert_eq!(
        ParamValue::OctetString(Vec::new()).param_type_name(),
        "OctetString"
    );
    assert_eq!(ParamValue::BigNum(Vec::new()).param_type_name(), "BigNum");
}

// =============================================================================
// Phase 3: ParamSet get/set/contains Tests
// =============================================================================
// Mirrors C `OSSL_PARAM_locate()` linear scan (now O(1) hash lookup).

#[test]
fn param_set_empty() {
    let set = ParamSet::new();
    assert_eq!(set.len(), 0);
    assert!(set.is_empty());
    assert_eq!(set.get("anything"), None);
}

#[test]
fn param_set_set_and_get() {
    let mut set = ParamSet::new();
    set.set("cipher", ParamValue::Utf8String("AES-256-GCM".into()));
    let val = set.get("cipher");
    assert_eq!(
        val,
        Some(&ParamValue::Utf8String("AES-256-GCM".to_string()))
    );
}

#[test]
fn param_set_contains() {
    let mut set = ParamSet::new();
    set.set("cipher", ParamValue::Utf8String("AES".into()));
    assert!(set.contains("cipher"));
    assert!(!set.contains("missing"));
}

#[test]
fn param_set_overwrite() {
    let mut set = ParamSet::new();
    set.set("key", ParamValue::Int32(1));
    set.set("key", ParamValue::Int32(2));
    assert_eq!(set.get("key"), Some(&ParamValue::Int32(2)));
    assert_eq!(set.len(), 1);
}

#[test]
fn param_set_remove() {
    let mut set = ParamSet::new();
    set.set("key", ParamValue::Int32(42));
    assert!(set.contains("key"));

    let removed = set.remove("key");
    assert_eq!(removed, Some(ParamValue::Int32(42)));
    // After removal, get returns None (Rule R5 — no sentinel)
    assert_eq!(set.get("key"), None);
    assert!(!set.contains("key"));
    assert!(set.is_empty());
}

#[test]
fn param_set_remove_missing_returns_none() {
    let mut set = ParamSet::new();
    // Removing a non-existent key returns None (Rule R5)
    assert_eq!(set.remove("ghost"), None);
}

#[test]
fn param_set_keys() {
    let mut set = ParamSet::new();
    set.set("alpha", ParamValue::Int32(1));
    set.set("beta", ParamValue::Int32(2));
    set.set("gamma", ParamValue::Int32(3));

    let mut keys: Vec<&str> = set.keys().collect();
    keys.sort();
    assert_eq!(keys, vec!["alpha", "beta", "gamma"]);
}

#[test]
fn param_set_len() {
    let mut set = ParamSet::new();
    set.set("a", ParamValue::Int32(1));
    set.set("b", ParamValue::UInt32(2));
    set.set("c", ParamValue::Int64(3));
    set.set("d", ParamValue::Real(4.0));
    set.set("e", ParamValue::Utf8String("five".into()));
    assert_eq!(set.len(), 5);
    assert!(!set.is_empty());
}

#[test]
fn param_set_iter() {
    let mut set = ParamSet::new();
    set.set("x", ParamValue::Int32(10));
    set.set("y", ParamValue::Int32(20));

    let mut pairs: Vec<(&str, &ParamValue)> = set.iter().collect();
    pairs.sort_by_key(|(k, _)| *k);
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0], ("x", &ParamValue::Int32(10)));
    assert_eq!(pairs[1], ("y", &ParamValue::Int32(20)));
}

#[test]
fn param_set_merge() {
    let mut base = ParamSet::new();
    base.set("shared", ParamValue::Int32(1));
    base.set("base_only", ParamValue::Utf8String("base".into()));

    let mut overlay = ParamSet::new();
    overlay.set("shared", ParamValue::Int32(999));
    overlay.set("overlay_only", ParamValue::Real(2.0));

    base.merge(&overlay);

    // Overlapping key: overlay value wins
    assert_eq!(base.get("shared"), Some(&ParamValue::Int32(999)));
    // Base-only key: preserved
    assert_eq!(
        base.get("base_only"),
        Some(&ParamValue::Utf8String("base".to_string()))
    );
    // Overlay-only key: added
    assert_eq!(base.get("overlay_only"), Some(&ParamValue::Real(2.0)));
    assert_eq!(base.len(), 3);
}

#[test]
fn param_set_get_missing_returns_none() {
    let set = ParamSet::new();
    // Rule R5: never returns sentinel, always None for missing keys
    assert_eq!(set.get("nonexistent"), None);
    assert_eq!(set.get(""), None);
    assert_eq!(set.get("any_key_at_all"), None);
}

// =============================================================================
// Phase 4: ParamSet get_typed() Type-Safe Extraction Tests
// =============================================================================

#[test]
fn get_typed_i32_success() {
    let mut set = ParamSet::new();
    set.set("key", ParamValue::Int32(42));
    let result: Result<i32, CommonError> = set.get_typed("key");
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn get_typed_string_success() {
    let mut set = ParamSet::new();
    set.set("key", ParamValue::Utf8String("hello".into()));
    let result: Result<String, CommonError> = set.get_typed("key");
    assert_eq!(result.unwrap(), "hello");
}

#[test]
fn get_typed_type_mismatch_error() {
    let mut set = ParamSet::new();
    set.set("key", ParamValue::Int32(42));
    let result: Result<String, CommonError> = set.get_typed("key");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, CommonError::ParamTypeMismatch { .. }),
        "Expected ParamTypeMismatch, got: {err:?}"
    );
}

#[test]
fn get_typed_missing_key_error() {
    let set = ParamSet::new();
    let result: Result<i32, CommonError> = set.get_typed("missing");
    assert!(result.is_err());
    let err = result.unwrap_err();
    match &err {
        CommonError::ParamNotFound { key } => {
            assert_eq!(key, "missing");
        }
        other => panic!("Expected ParamNotFound, got: {other:?}"),
    }
}

#[test]
fn get_typed_bool_from_int() {
    let mut set = ParamSet::new();

    // Int32(0) → false
    set.set("flag", ParamValue::Int32(0));
    let result: Result<bool, CommonError> = set.get_typed("flag");
    assert_eq!(result.unwrap(), false);

    // Int32(1) → true
    set.set("flag", ParamValue::Int32(1));
    let result: Result<bool, CommonError> = set.get_typed("flag");
    assert_eq!(result.unwrap(), true);

    // Non-zero also maps to true (matching C convention)
    set.set("flag", ParamValue::Int32(42));
    let result: Result<bool, CommonError> = set.get_typed("flag");
    assert_eq!(result.unwrap(), true);
}

#[test]
fn get_typed_u32_success() {
    let mut set = ParamSet::new();
    set.set("key", ParamValue::UInt32(255));
    let result: Result<u32, CommonError> = set.get_typed("key");
    assert_eq!(result.unwrap(), 255);
}

#[test]
fn get_typed_u64_success() {
    let mut set = ParamSet::new();
    set.set("key", ParamValue::UInt64(u64::MAX));
    let result: Result<u64, CommonError> = set.get_typed("key");
    assert_eq!(result.unwrap(), u64::MAX);
}

#[test]
fn get_typed_f64_success() {
    let mut set = ParamSet::new();
    set.set("key", ParamValue::Real(2.718));
    let result: Result<f64, CommonError> = set.get_typed("key");
    let val = result.unwrap();
    assert!((val - 2.718).abs() < f64::EPSILON);
}

#[test]
fn get_typed_vec_u8_success() {
    let mut set = ParamSet::new();
    set.set("key", ParamValue::OctetString(vec![0xCA, 0xFE]));
    let result: Result<Vec<u8>, CommonError> = set.get_typed("key");
    assert_eq!(result.unwrap(), vec![0xCA, 0xFE]);
}

// =============================================================================
// Phase 5: ParamBuilder Fluent API Tests
// =============================================================================
// Mirrors C `OSSL_PARAM_BLD` builder API from `crypto/param_build.c`.

#[test]
fn builder_empty_build() {
    let set = ParamBuilder::new().build();
    assert!(set.is_empty());
    assert_eq!(set.len(), 0);
}

#[test]
fn builder_push_i32() {
    let set = ParamBuilder::new().push_i32("bits", 2048).build();
    assert_eq!(set.get("bits"), Some(&ParamValue::Int32(2048)));
    assert_eq!(set.len(), 1);
}

#[test]
fn builder_push_u32() {
    let set = ParamBuilder::new().push_u32("key_length", 256).build();
    assert_eq!(set.get("key_length"), Some(&ParamValue::UInt32(256)));
}

#[test]
fn builder_push_i64() {
    let set = ParamBuilder::new().push_i64("offset", -9999).build();
    assert_eq!(set.get("offset"), Some(&ParamValue::Int64(-9999)));
}

#[test]
fn builder_push_u64() {
    let set = ParamBuilder::new().push_u64("max_size", u64::MAX).build();
    assert_eq!(set.get("max_size"), Some(&ParamValue::UInt64(u64::MAX)));
}

#[test]
fn builder_push_utf8() {
    let set = ParamBuilder::new()
        .push_utf8("digest", "SHA256".to_string())
        .build();
    assert_eq!(
        set.get("digest"),
        Some(&ParamValue::Utf8String("SHA256".to_string()))
    );
}

#[test]
fn builder_push_octet() {
    let iv = vec![0u8; 16];
    let set = ParamBuilder::new().push_octet("iv", iv.clone()).build();
    assert_eq!(set.get("iv"), Some(&ParamValue::OctetString(iv)));
}

#[test]
fn builder_push_bignum() {
    let bn_bytes = vec![0x01, 0x00, 0x01]; // 65537 in big-endian
    let set = ParamBuilder::new()
        .push_bignum("e", bn_bytes.clone())
        .build();
    assert_eq!(set.get("e"), Some(&ParamValue::BigNum(bn_bytes)));
}

#[test]
fn builder_push_f64() {
    let set = ParamBuilder::new().push_f64("epsilon", 1e-6).build();
    let val = set.get("epsilon");
    assert_eq!(val, Some(&ParamValue::Real(1e-6)));
}

#[test]
fn builder_fluent_chain() {
    // Chain multiple push calls in one expression — mirrors typical C OSSL_PARAM_BLD usage
    let set = ParamBuilder::new()
        .push_i32("bits", 4096)
        .push_utf8("algorithm", "RSA".to_string())
        .push_octet("seed", vec![0xAB, 0xCD])
        .push_u64("serial", 12345)
        .push_f64("threshold", 0.95)
        .build();

    assert_eq!(set.len(), 5);
    assert_eq!(set.get("bits"), Some(&ParamValue::Int32(4096)));
    assert_eq!(
        set.get("algorithm"),
        Some(&ParamValue::Utf8String("RSA".to_string()))
    );
    assert_eq!(
        set.get("seed"),
        Some(&ParamValue::OctetString(vec![0xAB, 0xCD]))
    );
    assert_eq!(set.get("serial"), Some(&ParamValue::UInt64(12345)));
    assert_eq!(set.get("threshold"), Some(&ParamValue::Real(0.95)));
}

#[test]
fn builder_duplicate_key_last_wins() {
    // When the same key is pushed twice, the last value wins
    // (matches HashMap::insert semantics, documented in ParamBuilder::build)
    let set = ParamBuilder::new()
        .push_i32("key", 1)
        .push_i32("key", 2)
        .build();
    assert_eq!(set.get("key"), Some(&ParamValue::Int32(2)));
    assert_eq!(set.len(), 1);
}

// =============================================================================
// Phase 6: FromParam Trait Conversion Tests
// =============================================================================

#[test]
fn from_param_i32() {
    let val = ParamValue::Int32(42);
    let result = i32::from_param(&val);
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn from_param_i32_negative() {
    let val = ParamValue::Int32(-100);
    let result = i32::from_param(&val);
    assert_eq!(result.unwrap(), -100);
}

#[test]
fn from_param_i32_boundary() {
    // Min and max i32 values
    assert_eq!(
        i32::from_param(&ParamValue::Int32(i32::MIN)).unwrap(),
        i32::MIN
    );
    assert_eq!(
        i32::from_param(&ParamValue::Int32(i32::MAX)).unwrap(),
        i32::MAX
    );
}

#[test]
fn from_param_u32() {
    let val = ParamValue::UInt32(100);
    assert_eq!(u32::from_param(&val).unwrap(), 100);
}

#[test]
fn from_param_u32_boundary() {
    assert_eq!(
        u32::from_param(&ParamValue::UInt32(u32::MAX)).unwrap(),
        u32::MAX
    );
    assert_eq!(u32::from_param(&ParamValue::UInt32(0)).unwrap(), 0);
}

#[test]
fn from_param_i64() {
    let val = ParamValue::Int64(-999_999_999_999);
    assert_eq!(i64::from_param(&val).unwrap(), -999_999_999_999);
}

#[test]
fn from_param_i64_from_i32_widens() {
    // FromParam for i64 accepts Int32 values (widening conversion)
    let val = ParamValue::Int32(42);
    assert_eq!(i64::from_param(&val).unwrap(), 42);
}

#[test]
fn from_param_u64() {
    let val = ParamValue::UInt64(u64::MAX);
    assert_eq!(u64::from_param(&val).unwrap(), u64::MAX);
}

#[test]
fn from_param_u64_from_u32_widens() {
    // FromParam for u64 accepts UInt32 values (widening conversion)
    let val = ParamValue::UInt32(255);
    assert_eq!(u64::from_param(&val).unwrap(), 255);
}

#[test]
fn from_param_f64() {
    let val = ParamValue::Real(2.71828);
    let result = f64::from_param(&val).unwrap();
    assert!((result - 2.71828).abs() < f64::EPSILON);
}

#[test]
fn from_param_string() {
    let val = ParamValue::Utf8String("SHA256".into());
    assert_eq!(String::from_param(&val).unwrap(), "SHA256");
}

#[test]
fn from_param_string_empty() {
    let val = ParamValue::Utf8String(String::new());
    assert_eq!(String::from_param(&val).unwrap(), "");
}

#[test]
fn from_param_vec_u8() {
    let val = ParamValue::OctetString(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(
        Vec::<u8>::from_param(&val).unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    );
}

#[test]
fn from_param_vec_u8_from_bignum() {
    // Vec<u8> extraction also accepts BigNum (both are byte vectors)
    let val = ParamValue::BigNum(vec![0x01, 0x00, 0x01]);
    assert_eq!(Vec::<u8>::from_param(&val).unwrap(), vec![0x01, 0x00, 0x01]);
}

#[test]
fn from_param_bool_true() {
    let val = ParamValue::Int32(1);
    assert_eq!(bool::from_param(&val).unwrap(), true);
}

#[test]
fn from_param_bool_false() {
    let val = ParamValue::Int32(0);
    assert_eq!(bool::from_param(&val).unwrap(), false);
}

#[test]
fn from_param_bool_nonzero_is_true() {
    // Any non-zero integer maps to true (C convention)
    assert_eq!(bool::from_param(&ParamValue::Int32(42)).unwrap(), true);
    assert_eq!(bool::from_param(&ParamValue::Int32(-1)).unwrap(), true);
    assert_eq!(bool::from_param(&ParamValue::UInt32(255)).unwrap(), true);
}

#[test]
fn from_param_bool_uint32_zero_is_false() {
    assert_eq!(bool::from_param(&ParamValue::UInt32(0)).unwrap(), false);
}

#[test]
fn from_param_type_mismatch() {
    // i32 from Utf8String → ParamTypeMismatch
    let val = ParamValue::Utf8String("hello".into());
    let result = i32::from_param(&val);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, CommonError::ParamTypeMismatch { .. }),
        "Expected ParamTypeMismatch, got: {err:?}"
    );
}

#[test]
fn from_param_type_mismatch_all_variants() {
    // Verify type mismatch for various incompatible conversions
    assert!(matches!(
        u32::from_param(&ParamValue::Utf8String("x".into())),
        Err(CommonError::ParamTypeMismatch { .. })
    ));
    assert!(matches!(
        i64::from_param(&ParamValue::Real(1.0)),
        Err(CommonError::ParamTypeMismatch { .. })
    ));
    assert!(matches!(
        f64::from_param(&ParamValue::Int32(1)),
        Err(CommonError::ParamTypeMismatch { .. })
    ));
    assert!(matches!(
        String::from_param(&ParamValue::Int64(1)),
        Err(CommonError::ParamTypeMismatch { .. })
    ));
    assert!(matches!(
        Vec::<u8>::from_param(&ParamValue::Real(1.0)),
        Err(CommonError::ParamTypeMismatch { .. })
    ));
    assert!(matches!(
        bool::from_param(&ParamValue::Utf8String("true".into())),
        Err(CommonError::ParamTypeMismatch { .. })
    ));
}

#[test]
fn from_param_i32_from_i64_narrowing() {
    // Rule R6 enforcement: i64::MAX cannot fit in i32, must fail.
    // The impl uses try_from() and maps the error to ParamTypeMismatch.
    let val = ParamValue::Int64(i64::MAX);
    let result = i32::from_param(&val);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, CommonError::ParamTypeMismatch { .. }),
        "Expected ParamTypeMismatch for narrowing overflow, got: {err:?}"
    );
}

#[test]
fn from_param_i32_from_i64_in_range_succeeds() {
    // An i64 value within i32 range should succeed via widening path
    let val = ParamValue::Int64(42);
    assert_eq!(i32::from_param(&val).unwrap(), 42);
}

#[test]
fn from_param_u32_from_u64_narrowing() {
    // Rule R6: u64::MAX cannot fit in u32
    let val = ParamValue::UInt64(u64::MAX);
    let result = u32::from_param(&val);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CommonError::ParamTypeMismatch { .. }
    ));
}

#[test]
fn from_param_u32_from_u64_in_range_succeeds() {
    let val = ParamValue::UInt64(100);
    assert_eq!(u32::from_param(&val).unwrap(), 100);
}

// =============================================================================
// CastOverflow Error Variant Verification
// =============================================================================
// Verifies that CommonError::CastOverflow can be constructed from
// std::num::TryFromIntError, validating the #[from] conversion chain
// used by Rule R6 enforcement across the codebase.

#[test]
fn cast_overflow_from_try_from_int_error() {
    // Create a TryFromIntError by attempting an impossible conversion
    let try_err = u8::try_from(256u16).unwrap_err();
    let common_err: CommonError = CommonError::CastOverflow(try_err);
    assert!(
        matches!(common_err, CommonError::CastOverflow(_)),
        "Expected CastOverflow variant"
    );
    // Verify Display output is meaningful
    let display = format!("{common_err}");
    assert!(
        display.contains("numeric cast overflow"),
        "Display should mention numeric cast overflow, got: {display}"
    );
}

#[test]
fn invalid_argument_error_from_param_operations() {
    // Verify CommonError::InvalidArgument is produced by from_text with bad hex
    let result = from_text("key", "0xGG");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, CommonError::InvalidArgument(_)),
        "Expected InvalidArgument for bad hex, got: {err:?}"
    );
}

// =============================================================================
// Phase 7: ParamSet Duplication Tests
// =============================================================================
// Mirrors `crypto/params_dup.c`.

#[test]
fn param_set_clone() {
    let mut original = ParamSet::new();
    original.set("key", ParamValue::Int32(42));
    original.set("name", ParamValue::Utf8String("test".into()));

    let mut cloned = original.clone();

    // Verify deep copy — contents match
    assert_eq!(cloned.get("key"), Some(&ParamValue::Int32(42)));
    assert_eq!(
        cloned.get("name"),
        Some(&ParamValue::Utf8String("test".to_string()))
    );

    // Modify clone — original is unaffected
    cloned.set("key", ParamValue::Int32(999));
    assert_eq!(original.get("key"), Some(&ParamValue::Int32(42)));
    assert_eq!(cloned.get("key"), Some(&ParamValue::Int32(999)));
}

#[test]
fn param_set_duplicate() {
    let mut original = ParamSet::new();
    original.set("algo", ParamValue::Utf8String("AES".into()));
    original.set("bits", ParamValue::UInt32(256));
    original.set("iv", ParamValue::OctetString(vec![0u8; 12]));

    let dup = original.duplicate();

    // Verify duplicate contents match original
    assert_eq!(dup.len(), 3);
    assert_eq!(
        dup.get("algo"),
        Some(&ParamValue::Utf8String("AES".to_string()))
    );
    assert_eq!(dup.get("bits"), Some(&ParamValue::UInt32(256)));
    assert_eq!(dup.get("iv"), Some(&ParamValue::OctetString(vec![0u8; 12])));
}

#[test]
fn param_set_duplicate_is_independent() {
    let mut original = ParamSet::new();
    original.set("data", ParamValue::OctetString(vec![1, 2, 3]));

    let dup = original.duplicate();

    // Modify original — duplicate is unaffected
    original.set("data", ParamValue::OctetString(vec![9, 9, 9]));
    assert_eq!(
        dup.get("data"),
        Some(&ParamValue::OctetString(vec![1, 2, 3]))
    );
}

#[test]
fn param_set_duplicate_empty() {
    let original = ParamSet::new();
    let dup = original.duplicate();
    assert!(dup.is_empty());
    assert_eq!(dup.len(), 0);
}

// =============================================================================
// Phase 8: Param from Text Tests
// =============================================================================
// Mirrors `crypto/params_from_text.c`.

#[test]
fn from_text_integer() {
    // Positive integer → Int64
    let val = from_text("key", "42").unwrap();
    assert_eq!(val, ParamValue::Int64(42));
}

#[test]
fn from_text_zero() {
    let val = from_text("key", "0").unwrap();
    assert_eq!(val, ParamValue::Int64(0));
}

#[test]
fn from_text_negative_integer() {
    let val = from_text("key", "-7").unwrap();
    assert_eq!(val, ParamValue::Int64(-7));
}

#[test]
fn from_text_large_positive_integer() {
    // Value larger than i64::MAX → UInt64
    let large = format!("{}", u64::MAX);
    let val = from_text("key", &large).unwrap();
    assert_eq!(val, ParamValue::UInt64(u64::MAX));
}

#[test]
fn from_text_hex_bytes() {
    let val = from_text("key", "0xDEADBEEF").unwrap();
    assert_eq!(val, ParamValue::OctetString(vec![0xDE, 0xAD, 0xBE, 0xEF]));
}

#[test]
fn from_text_hex_bytes_lowercase() {
    let val = from_text("key", "0xdeadbeef").unwrap();
    assert_eq!(val, ParamValue::OctetString(vec![0xDE, 0xAD, 0xBE, 0xEF]));
}

#[test]
fn from_text_hex_bytes_uppercase_prefix() {
    let val = from_text("key", "0XCAFE").unwrap();
    assert_eq!(val, ParamValue::OctetString(vec![0xCA, 0xFE]));
}

#[test]
fn from_text_hex_bytes_empty() {
    // "0x" with no hex chars → empty OctetString
    let val = from_text("key", "0x").unwrap();
    assert_eq!(val, ParamValue::OctetString(Vec::new()));
}

#[test]
fn from_text_hex_bytes_odd_length_error() {
    // Odd-length hex string → InvalidArgument error
    let result = from_text("key", "0xABC");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CommonError::InvalidArgument(_)
    ));
}

#[test]
fn from_text_hex_bytes_invalid_char_error() {
    // Non-hex character → InvalidArgument error
    let result = from_text("key", "0xGGHH");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CommonError::InvalidArgument(_)
    ));
}

#[test]
fn from_text_string() {
    // Non-numeric text → Utf8String
    let val = from_text("key", "hello").unwrap();
    assert_eq!(val, ParamValue::Utf8String("hello".to_string()));
}

#[test]
fn from_text_string_algorithm_name() {
    let val = from_text("key", "SHA256").unwrap();
    assert_eq!(val, ParamValue::Utf8String("SHA256".to_string()));
}

#[test]
fn from_text_float() {
    let val = from_text("key", "3.14").unwrap();
    assert_eq!(val, ParamValue::Real(3.14));
}

#[test]
fn from_text_float_scientific() {
    let val = from_text("key", "1.5e2").unwrap();
    assert_eq!(val, ParamValue::Real(150.0));
}

#[test]
fn from_text_float_negative() {
    // "-3.14" contains '.', parses as float
    let val = from_text("key", "-3.14").unwrap();
    assert_eq!(val, ParamValue::Real(-3.14));
}

#[test]
fn from_text_empty_string() {
    // Empty string → Utf8String("")
    let val = from_text("key", "").unwrap();
    assert_eq!(val, ParamValue::Utf8String(String::new()));
}

// =============================================================================
// Display and Debug Trait Coverage
// =============================================================================

#[test]
fn param_value_display() {
    // Verify Display impl produces non-empty strings for all variants
    let variants: Vec<ParamValue> = vec![
        ParamValue::Int32(42),
        ParamValue::UInt32(100),
        ParamValue::Int64(-1),
        ParamValue::UInt64(999),
        ParamValue::Real(3.14),
        ParamValue::Utf8String("test".into()),
        ParamValue::OctetString(vec![1, 2, 3]),
        ParamValue::BigNum(vec![0xFF]),
    ];

    for val in &variants {
        let display = format!("{val}");
        assert!(
            !display.is_empty(),
            "ParamValue::{} Display should be non-empty",
            val.param_type_name()
        );
    }
}

#[test]
fn param_value_debug() {
    // Verify Debug impl is available (derives Debug)
    let val = ParamValue::Int32(42);
    let debug = format!("{val:?}");
    assert!(debug.contains("Int32"));
    assert!(debug.contains("42"));
}

#[test]
fn param_set_debug() {
    let mut set = ParamSet::new();
    set.set("key", ParamValue::Int32(1));
    let debug = format!("{set:?}");
    assert!(debug.contains("ParamSet"));
}

#[test]
fn param_builder_debug() {
    let builder = ParamBuilder::new().push_i32("x", 1);
    let debug = format!("{builder:?}");
    assert!(debug.contains("ParamBuilder"));
}

// =============================================================================
// ParamValue Clone and PartialEq Coverage
// =============================================================================

#[test]
fn param_value_clone_and_eq() {
    let original = ParamValue::OctetString(vec![0xCA, 0xFE, 0xBA, 0xBE]);
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn param_value_ne() {
    assert_ne!(ParamValue::Int32(1), ParamValue::Int32(2));
    assert_ne!(ParamValue::Int32(42), ParamValue::UInt32(42));
    assert_ne!(
        ParamValue::Utf8String("a".into()),
        ParamValue::Utf8String("b".into())
    );
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn param_set_many_entries() {
    // Verify ParamSet works with many entries
    let mut set = ParamSet::new();
    for i in 0..100u32 {
        // Use leaked strings to get &'static str for test purposes
        let key: &'static str = Box::leak(format!("key_{i}").into_boxed_str());
        set.set(key, ParamValue::UInt32(i));
    }
    assert_eq!(set.len(), 100);
    assert!(set.contains("key_0"));
    assert!(set.contains("key_99"));
    assert_eq!(set.get("key_50"), Some(&ParamValue::UInt32(50)));
}

#[test]
fn param_value_int32_extremes() {
    assert_eq!(ParamValue::Int32(i32::MIN).as_i32(), Some(i32::MIN));
    assert_eq!(ParamValue::Int32(i32::MAX).as_i32(), Some(i32::MAX));
}

#[test]
fn param_value_real_special_values() {
    // Positive/negative zero
    let pos_zero = ParamValue::Real(0.0);
    let neg_zero = ParamValue::Real(-0.0);
    assert_eq!(pos_zero.as_f64(), Some(0.0));
    assert_eq!(neg_zero.as_f64(), Some(-0.0));

    // Very small/large finite values
    assert_eq!(ParamValue::Real(f64::MIN).as_f64(), Some(f64::MIN));
    assert_eq!(ParamValue::Real(f64::MAX).as_f64(), Some(f64::MAX));
}

#[test]
fn builder_all_types_combined() {
    // Build a ParamSet with all 8 value types to verify comprehensive coverage
    let set = ParamBuilder::new()
        .push_i32("i32", -42)
        .push_u32("u32", 42)
        .push_i64("i64", -999_999)
        .push_u64("u64", 999_999)
        .push_f64("f64", 1.618)
        .push_utf8("str", "golden ratio".to_string())
        .push_octet("oct", vec![0x01, 0x02])
        .push_bignum("bn", vec![0xFF, 0xFE, 0xFD])
        .build();

    assert_eq!(set.len(), 8);
    assert_eq!(set.get("i32"), Some(&ParamValue::Int32(-42)));
    assert_eq!(set.get("u32"), Some(&ParamValue::UInt32(42)));
    assert_eq!(set.get("i64"), Some(&ParamValue::Int64(-999_999)));
    assert_eq!(set.get("u64"), Some(&ParamValue::UInt64(999_999)));
    assert_eq!(set.get("f64"), Some(&ParamValue::Real(1.618)));
    assert_eq!(
        set.get("str"),
        Some(&ParamValue::Utf8String("golden ratio".to_string()))
    );
    assert_eq!(
        set.get("oct"),
        Some(&ParamValue::OctetString(vec![0x01, 0x02]))
    );
    assert_eq!(
        set.get("bn"),
        Some(&ParamValue::BigNum(vec![0xFF, 0xFE, 0xFD]))
    );
}

#[test]
fn param_set_default_is_empty() {
    // ParamSet derives Default — verify it produces an empty set
    let set = ParamSet::default();
    assert!(set.is_empty());
    assert_eq!(set.len(), 0);
}

#[test]
fn param_builder_default_builds_empty() {
    // ParamBuilder derives Default — verify it builds an empty set
    let set = ParamBuilder::default().build();
    assert!(set.is_empty());
}
