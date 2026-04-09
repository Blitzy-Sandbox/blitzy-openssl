Welcome to the OpenSSL Project
==============================

[![openssl logo]][www.openssl.org]

[![github actions ci badge]][github actions ci]
[![Nightly OS Zoo ci badge](https://github.com/openssl/openssl/actions/workflows/os-zoo.yml/badge.svg)](https://github.com/openssl/openssl/actions/workflows/os-zoo.yml)
[![Provider Compatibility](https://github.com/openssl/openssl/actions/workflows/provider-compatibility.yml/badge.svg)](https://github.com/openssl/openssl/actions/workflows/provider-compatibility.yml)
[![Quic Interop](https://github.com/openssl/openssl/actions/workflows/run_quic_interop.yml/badge.svg)](https://github.com/openssl/openssl/actions/workflows/run_quic_interop.yml)
[![Daily checks](https://github.com/openssl/openssl/actions/workflows/run-checker-daily.yml/badge.svg)](https://github.com/openssl/openssl/actions/workflows/run-checker-daily.yml)
[![LFX Health Score](https://insights.linuxfoundation.org/api/badge/health-score?project=openssl)](https://insights.linuxfoundation.org/project/openssl)

OpenSSL is a robust, commercial-grade, full-featured Open Source Toolkit
for the Transport Layer Security (TLS, formerly SSL), Datagram TLS (DTLS), and QUIC protocols.

The protocol implementations are based on a full-strength general purpose
cryptographic library, which can also be used stand-alone. Also included is a
cryptographic module validated to conform with FIPS standards.

OpenSSL is descended from the SSLeay library developed by Eric A. Young
and Tim J. Hudson.

The official Home Page of the OpenSSL Project is [www.openssl.org].

Table of Contents
=================

 - [Overview](#overview)
 - [Download](#download)
 - [Build and Install](#build-and-install)
 - [Rust Workspace (openssl-rs)](#rust-workspace-openssl-rs)
 - [Documentation](#documentation)
 - [License](#license)
 - [Support](#support)
 - [Contributing](#contributing)
 - [Legalities](#legalities)

Overview
========

The OpenSSL toolkit includes:

- **libssl**
  an implementation of all TLS protocol versions up to TLSv1.3 ([RFC 8446]),
  DTLS protocol versions up to DTLSv1.2 ([RFC 6347]) and
  the QUIC version 1 protocol ([RFC 9000]).

- **libcrypto**
  a full-strength general purpose cryptographic library. It constitutes the
  basis of the TLS implementation, but can also be used independently.

- **openssl**
  the OpenSSL command line tool, a swiss army knife for cryptographic tasks,
  testing and analyzing. It can be used for
  - creation of key parameters
  - creation of X.509 certificates, CSRs and CRLs
  - calculation of message digests
  - encryption and decryption
  - SSL/TLS/DTLS and client and server tests
  - QUIC client tests
  - handling of S/MIME signed or encrypted mail
  - and more...

Download
========

For Production Use
------------------

Source code tarballs of the official releases can be downloaded from
[openssl-library.org/source/](https://openssl-library.org/source/).
The OpenSSL project does not distribute the toolkit in binary form.

However, for a large variety of operating systems precompiled versions
of the OpenSSL toolkit are available. In particular, on Linux and other
Unix operating systems, it is normally recommended to link against the
precompiled shared libraries provided by the distributor or vendor.

We also maintain a list of third parties that produce OpenSSL binaries for
various Operating Systems (including Windows) on the [Binaries] page on our
wiki.

For Testing and Development
---------------------------

Although testing and development could in theory also be done using
the source tarballs, having a local copy of the git repository with
the entire project history gives you much more insight into the
code base.

The main OpenSSL Git repository is private.
There is a public GitHub mirror of it at [github.com/openssl/openssl],
which is updated automatically from the former on every commit.

A local copy of the Git repository can be obtained by cloning it from
the GitHub mirror using

    git clone https://github.com/openssl/openssl.git

If you intend to contribute to OpenSSL, either to fix bugs or contribute
new features, you need to fork the GitHub mirror and clone your public fork
instead.

    git clone https://github.com/yourname/openssl.git

This is necessary because all development of OpenSSL nowadays is done via
GitHub pull requests. For more details, see [Contributing](#contributing).

Build and Install
=================

After obtaining the Source, have a look at the [INSTALL](INSTALL.md) file for
detailed instructions about building and installing OpenSSL. For some
platforms, the installation instructions are amended by a platform specific
document.

 * [Notes for UNIX-like platforms](NOTES-UNIX.md)
 * [Notes for Android platforms](NOTES-ANDROID.md)
 * [Notes for Windows platforms](NOTES-WINDOWS.md)
 * [Notes for the DOS platform with DJGPP](NOTES-DJGPP.md)
 * [Notes for the OpenVMS platform](NOTES-VMS.md)
 * [Notes on Perl](NOTES-PERL.md)
 * [Notes on Valgrind](NOTES-VALGRIND.md)

Specific notes on upgrading to OpenSSL 3.x from previous versions can be found
in the [ossl-guide-migration(7ossl)] manual page.

Rust Workspace (openssl-rs)
===========================

This repository includes a complete Rust workspace under the `crates/`
directory containing an idiomatic Rust rewrite of the OpenSSL C source code.
The workspace targets Rust edition 2021 with a minimum supported Rust version
(MSRV) of 1.81.0. The original C source tree is preserved alongside the Rust
crates for validation reference and continued FFI consumer compatibility.

Quick Start
-----------

The following steps enable a complete build-and-test cycle from a clean machine.
No additional configuration is required beyond the Rust toolchain.

### Prerequisites

Install the Rust toolchain at the project's MSRV:

    rustup install 1.81.0
    rustup default 1.81.0

Optionally install auxiliary tools for coverage and security auditing:

    cargo install cargo-llvm-cov cargo-deny cargo-audit

### Build

Build all crates in release mode:

    cargo build --workspace --release

Build with warnings-as-errors (matches CI configuration):

    RUSTFLAGS="-D warnings" cargo build --workspace

### Test

Run the full test suite across all crates:

    cargo test --workspace

### Lint

Run Clippy with all project lints enforced:

    cargo clippy --workspace -- -D warnings

Check formatting:

    cargo fmt --all -- --check

### Coverage

Generate an LLVM source-based coverage report and enforce the 80% line
coverage threshold:

    cargo llvm-cov --workspace --fail-under-lines 80

### Security Audit

Run dependency ban checks (advisory, license, and source policy):

    cargo deny check

Scan for known vulnerabilities in the RustSec advisory database:

    cargo audit

Workspace Structure
-------------------

The workspace is organized into seven crates under the `crates/` directory:

| Crate | Description |
|-------|-------------|
| `openssl-common` | Shared types, error handling, config, observability |
| `openssl-crypto` | libcrypto equivalent (algorithms, EVP, BIO, X.509) |
| `openssl-ssl` | libssl equivalent (TLS/DTLS/QUIC/ECH) |
| `openssl-provider` | Provider system (trait-based dispatch) |
| `openssl-fips` | FIPS module (self-test, KATs, integrity) |
| `openssl-cli` | CLI binary (clap-based subcommands) |
| `openssl-ffi` | C ABI compatibility layer (cbindgen) |

The dependency graph flows downward: `openssl-cli` depends on `openssl-ssl`
and `openssl-crypto`, which both depend on `openssl-common`. The `openssl-ffi`
crate re-exports safe wrappers as `extern "C"` functions so that existing C
consumers can continue to link against the library.

Domain Context
--------------

### Provider-Based Dispatch

All cryptographic algorithms are delivered through a provider architecture.
The C `OSSL_DISPATCH` function pointer tables are replaced by Rust traits
(`DigestProvider`, `CipherProvider`, `SignatureProvider`, and others), with
the default, legacy, base, null, and FIPS providers each implementing the
relevant traits. Algorithm selection uses `Box<dyn AlgorithmProvider>` for
runtime dispatch while eliminating function pointer unsafety.

### Async Boundaries

The QUIC stack (`openssl-ssl::quic`) uses `tokio` for its event-driven
reactor pattern. All other code — including `openssl-crypto`, the TLS/DTLS
state machine, and the record layer — is fully synchronous. Exactly one
`tokio::runtime::Runtime` instance is created in `openssl-cli::main()`, and
all other async components receive a `tokio::runtime::Handle` (rule R1).
Nested `block_on` calls are forbidden.

### FIPS Isolation

The `openssl-fips` crate is independently compilable and depends only on
`openssl-common` and selected items from `openssl-crypto`. It never imports
from `openssl-ssl`, `openssl-cli`, or `openssl-provider`. Self-test Known
Answer Tests (KATs) execute at module load time, and the FIPS state machine
follows the sequence: `PowerOn → SelfTesting → Operational | Error`.

Common Pitfalls
---------------

New developers should be aware of the following project-wide rules enforced
by CI and workspace lint configuration:

- **No `unsafe` outside `openssl-ffi`** (rule R8).
  The `#[deny(unsafe_code)]` lint is set at the workspace level. Only the
  `openssl-ffi` crate is permitted to use `unsafe` blocks, and each block
  must carry a `// SAFETY:` justification comment.

- **No bare `as` casts for narrowing** (rule R6).
  The workspace denies `clippy::cast_possible_truncation`,
  `clippy::cast_sign_loss`, and `clippy::cast_possible_wrap`. Use
  `TryFrom`, `saturating_cast`, or `clamp` instead.

- **No holding `std::sync::Mutex` across `.await`** (rule R2).
  The `clippy::await_holding_lock` lint is set to `deny`. Use
  `tokio::sync::Mutex` when a lock must be held across an await point
  and prefer `std::sync::Mutex` in synchronous code.

- **Config field propagation** (rule R3).
  Every field on every config, options, or state struct must have both a
  write-site and a read-site reachable from the entry point. Unread fields
  must be annotated with `// UNREAD: reserved`.

- **Warning-free builds** (rule R9).
  CI runs with `RUSTFLAGS="-D warnings"`. Module-level `#[allow(warnings)]`
  or `#[allow(unused)]` attributes are forbidden. Individual `#[allow]`
  annotations require a justification comment.

Deliverable Artifacts
---------------------

The following documentation artifacts accompany the Rust workspace:

| Artifact | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate boundary justifications, runtime topology, consistency delta |
| [DECISION_LOG.md](DECISION_LOG.md) | Non-trivial decision rationale table |
| [TRACEABILITY.md](TRACEABILITY.md) | Bidirectional C → Rust mapping (100% coverage) |
| [FEATURE_PARITY.md](FEATURE_PARITY.md) | Source feature → Rust implementation status matrix |
| [CONFIG_PROPAGATION_AUDIT.md](CONFIG_PROPAGATION_AUDIT.md) | Per-field write-site → read-site audit |
| [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md) | Workload benchmarks: wall-clock and memory, Rust vs C |
| [UNSAFE_AUDIT.md](UNSAFE_AUDIT.md) | Count, locations, and justifications of `unsafe` blocks |
| [GATE_COMPLIANCE.md](GATE_COMPLIANCE.md) | 18-line pass/fail summary for all validation gates |

Extension Guidance
------------------

Suggested next tasks for contributors:

1. **Platform-specific acceleration** — Add `core::arch` intrinsics for
   AES-NI, SHA-NI, and ARM NEON in dedicated `accel` submodules to close
   any remaining performance gap with the C plus assembly baseline.

2. **Additional FIPS KAT vectors** — Expand the Known Answer Test suite in
   `openssl-fips` with test vectors from NIST CAVP and ACVP programs.

3. **Async TLS** — Explore `AsyncRead` / `AsyncWrite` wrappers for the TLS
   state machine, enabling native async TLS without `spawn_blocking` bridges.

4. **Fuzz targets** — Port the 38 existing C fuzz harnesses in `fuzz/` to
   Rust using `cargo-fuzz` and `libfuzzer-sys`.

5. **WASM support** — Investigate the `wasm32-unknown-unknown` target for
   `openssl-crypto` (excluding platform-specific modules).

6. **Provider plugin API** — Design a stable dynamic loading interface for
   third-party Rust providers registered at runtime.

C Source Preservation
---------------------

The original C source tree (`crypto/`, `ssl/`, `providers/`, `apps/`,
`include/`, `test/`) is preserved in its entirety alongside the Rust
workspace. These files serve as:

- The **validation reference** for feature parity verification
- The **FFI consumer baseline** ensuring existing C callers continue to link
- The **test oracle** against which Rust output is compared

Do **not** delete, move, or modify the original C source files. The existing
C-based build system (`Configure`, `Configurations/`, `util/`) and the CI
workflows under `.github/workflows/` remain fully operational.

Documentation
=============

README Files
------------

There are some README.md files in the top level of the source distribution
containing additional information on specific topics.

 * [Information about the OpenSSL QUIC protocol implementation](README-QUIC.md)
 * [Information about the OpenSSL Provider architecture](README-PROVIDERS.md)
 * [Information about using the OpenSSL FIPS validated module](README-FIPS.md)

The OpenSSL Guide
-----------------

There are some tutorial and introductory pages on some important OpenSSL topics
within the [OpenSSL Guide].

Manual Pages
------------

The manual pages for the master branch and all current stable releases are
available online.

- [OpenSSL master](https://docs.openssl.org/master/)
- [OpenSSL 3.6](https://docs.openssl.org/3.6/)
- [OpenSSL 3.5](https://docs.openssl.org/3.5/)
- [OpenSSL 3.4](https://docs.openssl.org/3.4/)
- [OpenSSL 3.3](https://docs.openssl.org/3.3/)
- [OpenSSL 3.2](https://docs.openssl.org/3.2/)
- [OpenSSL 3.0](https://docs.openssl.org/3.0/)

Demos
-----

There are numerous source code demos for using various OpenSSL capabilities in the
[demos subfolder](./demos).

Wiki
----

There is a [GitHub Wiki] which is currently not very active.

License
=======

OpenSSL is licensed under the Apache License 2.0, which means that
you are free to get and use it for commercial and non-commercial
purposes as long as you fulfill its conditions.

See the [LICENSE.txt](LICENSE.txt) file for more details.

Support
=======

There are various ways to get in touch. The correct channel depends on
your requirement. See the [SUPPORT](SUPPORT.md) file for more details.

Contributing
============

If you are interested and willing to contribute to the OpenSSL project,
please take a look at the [CONTRIBUTING](CONTRIBUTING.md) file.

Legalities
==========

A number of nations restrict the use or export of cryptography. If you are
potentially subject to such restrictions, you should seek legal advice before
attempting to develop or distribute cryptographic code.

Copyright
=========

Copyright (c) 1998-2025 The OpenSSL Project Authors

Copyright (c) 1995-1998 Eric A. Young, Tim J. Hudson

All rights reserved.

<!-- Links  -->

[www.openssl.org]:
    <https://www.openssl.org>
    "OpenSSL Homepage"

[github.com/openssl/openssl]:
    <https://github.com/openssl/openssl>
    "OpenSSL GitHub Mirror"

[GitHub Wiki]:
    <https://github.com/openssl/openssl/wiki>
    "OpenSSL Wiki"

[ossl-guide-migration(7ossl)]:
    <https://docs.openssl.org/master/man7/ossl-guide-migration>
    "OpenSSL Migration Guide"

[RFC 8446]:
     <https://tools.ietf.org/html/rfc8446>

[RFC 6347]:
     <https://tools.ietf.org/html/rfc6347>

[RFC 9000]:
     <https://tools.ietf.org/html/rfc9000>

[Binaries]:
    <https://github.com/openssl/openssl/wiki/Binaries>
    "List of third party OpenSSL binaries"

[OpenSSL Guide]:
    <https://docs.openssl.org/master/man7/ossl-guide-introduction>
    "An introduction to OpenSSL"

<!-- Logos and Badges -->

[openssl logo]:
    doc/images/openssl.svg
    "OpenSSL Logo"

[github actions ci badge]:
    <https://github.com/openssl/openssl/workflows/GitHub%20CI/badge.svg>
    "GitHub Actions CI Status"

[github actions ci]:
    <https://github.com/openssl/openssl/actions/workflows/ci.yml>
    "GitHub Actions CI"

[appveyor badge]:
    <https://ci.appveyor.com/api/projects/status/8e10o7xfrg73v98f/branch/master?svg=true>
    "AppVeyor Build Status"

[appveyor jobs]:
    <https://ci.appveyor.com/project/openssl/openssl/branch/master>
    "AppVeyor Jobs"
