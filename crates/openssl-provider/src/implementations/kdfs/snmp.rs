//! SNMP Key Derivation Function (RFC 3414, Section A.2).
//!
//! Source: `providers/implementations/kdfs/snmpkdf.c`

use crate::traits::AlgorithmDescriptor;
use crate::implementations::algorithm;

/// Returns algorithm descriptors for SNMPKDF.
#[must_use]
pub fn descriptors() -> Vec<AlgorithmDescriptor> {
    vec![
        algorithm(
            &["SNMPKDF"],
            "provider=default",
            "SNMP Key Derivation Function (RFC 3414)",
        ),
    ]
}
