# Pinned real-root lookup

This component replaces the compact-bundle verifier only for Stratum's system-certificate mode. Explicit custom-CA and plain-TCP modes are unchanged. It requires ESP-IDF 6.0.2's native trusted-certificate callback API, not the SDK's synthetic-root cross-sign option.

`roots.inc` contains exactly the full DER forms of the existing 118 approved roots in `certificates/cacert-2026-10-20.pem`. It adds no trust anchors. Regenerate it with the SDK Python:

```sh
python tools/generate_pinned_roots.py
python tools/test_ca_bundle.py
```

The first-CN comparison only limits allocations. It deliberately accepts a superset of native name matches, including all roots without CN. mbedTLS still compares the complete distinguished name and verifies signatures, constraints, key policy, hostnames, and the configured validity policy. No verification flags are cleared. ESP-Miner's inherited time/date-check setting is not changed here.

Each lookup allocates at most seven candidate roots from at most 6,969 DER input bytes. These are input bounds, not complete native heap bounds. Successful lookup transfers ownership to mbedTLS; failure frees the complete partial list before returning an error. All allocations use the native mbedTLS allocator domain. Only immutable bytes are shared across clients.

Attach this helper only on the bundle-backed path, before the TLS configuration is used. It removes the old bundle post-verification hook on a reused configuration. Do not use it to replace an unrelated application's security callback or custom-CA/CRL policy.

Private acceptance evidence includes complete frozen cross-sign regressions, all 12 incident denials, malformed roots, all-root and complete-verification allocation sweeps, concurrent native lifecycles, actual ESP SSL transport with both enabled TLS versions, and a full ESP32-S3 application build. That evidence is not device execution or deployment approval. Hardware heap/PSRAM, task-stack headroom, and real pool-specific TLS acceptance remain separate gates.
