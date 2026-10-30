# SDK certificate-bundle regression

Run `python3 tools/test_native_roots.py --idf-path "$IDF_PATH" --output "$PWD/native-results"` with a new output directory. Requirements: Python 3, CMake, a C compiler with pthreads, and `cryptography` for the SDK certificate generator. Use an unmodified ESP-IDF v6.0.2 checkout with its mbedTLS submodule initialized. The runner checks SDK commit `7101770dc6db2667b3c477cc31365dd1acd6db4e` and mbedTLS commit `6cc42afad309e861f4c07e6f106e2ab14a9cb8e5`. It compiles their native libraries and exact SDK bundle implementation with platform/logging shims; it never opens sockets, serial ports, or devices or modifies SDK sources.

The production fix enables `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY=y`. Its SDK CA callback finds the approved GTS Root R4 directly when verifying WE1, without requiring the redundant cross-sign's absent legacy GlobalSign issuer. No extra component or trust store is needed. `baseline.c` dispatches through the CA callback when installed, preserving the configured profile and verification callback, rather than incorrectly using only `conf.ca_chain`.

## Frozen fixtures

Public chains were captured on **2026-10-30 UTC**, using OpenSSL 3 `s_client -showcerts -connect HOST:PORT -servername HOST`:

| Fixture | Provenance / purpose | Stock | Cross-sign |
| --- | --- | --- | --- |
| `braiins.com-full.pem` | `braiins.com:443`: leaf → WE1 → GTS R4 cross-signed by legacy GlobalSign (absent from pinned bundle) | reject | accept |
| `braiins.com-short.pem` | Same capture, dropping only its final certificate | accept | accept |
| `public-pool.io-full.pem` | `public-pool.io:4333`: leaf → Let's Encrypt YE2 → Root YE → ISRG Root X2 cross-signed by X1 | accept | accept |
| `attacker-full.pem` | Synthetic braiins.com leaf signed by a same-subject, different-key GTS R4 impostor | reject | reject |
| `bad-signature.pem` | Full Braiins chain, last DER byte of leaf signature XOR 1 | reject | reject |
| `self.pem` | Synthetic self-signed braiins.com leaf; tested with its actual hostname | reject | reject |

Braiins Stratum endpoints are plain TCP; its **website** is only a neutral chain-building fixture. These fixtures do not imply firmware connections to the named websites. Synthetic certificate keys were generated solely for these fixtures and were never serialized. `fixtures/sha256.json` binds the exact PEM files. The attacker root uses the captured GTS R4 subject but a freshly generated P-256 key, not Google's key.

Both SDK configurations use identical bundle bytes generated from the existing `certificates/cacert-2026-10-20.pem`. Both reject all 12 chains from the existing checksum-bound incident ZIP, without committing unpacked copies. The suite records 42 results: the six fixtures, three explicit wrong-host cases, and all 12 incident chains in each mode. Wrong-host checks on otherwise trusted chains require the hostname-mismatch bit, not merely a transport or trust error. All successful verifications require zero flags. The native build follows firmware's inherited disabled time/date policy; archived fixture validity is not live endpoint acceptance.

`commands.log` and `results.json` are local evidence, not committed outputs. Native verifier tests are distinct from configured ESP SSL transport execution and full ESP32-S3 builds. Local Darwin execution does not claim Linux CI has run. None establishes device heap/PSRAM, task-stack headroom, or real pool operation, or authorizes installation.
