# mdoc_validation Crate Draft

## Purpose

`mdoc_validation` will provide validation logic for:

1. **Reader authentication certificate validation** according to ISO/IEC 18013-5 (section 12.8.3, inspection procedure for mdoc reader authentication certificate validation).
2. **MSO revocation checks** according to ISO/IEC 18013-5 (section 12.3.6).

This document captures implementation assumptions, required inputs, and open design decisions before coding starts.

## Standards Reference

Primary reference:
- ISO working draft: https://github.com/ISOWG10/ISO-18013/blob/main/Working%20Documents/Working%20Draft%20ISO_IEC_18013-5_second-edition_CD_ballot_resolution_v4.pdf

Important sections to align with:
- 12.8.3: inspection procedure for mdoc reader authentication certificate validation
- 12.3.6: MSO revocation
- 12.3.6.2: certificate source rules for status checks
- Annex B.3.2: CRL validation example

---

## #1 `certificate_validation`

### Goal
Validate an mdoc reader authentication certificate chain (`x5chain`) against an IACA root certificate (`iacacert`) provided as DER.

### Inputs
- `iacacert_der: &[u8]` (DER-encoded IACA root certificate)
- `x5chain: Vec<Vec<u8>>` (DER-encoded certificates, leaf first expected)
- Validation time (`now`) from system clock (or injectable for testing)

### Additional helper provided by this crate
Even though validation accepts DER directly, this crate should also provide a helper function to download IACA certificate DER from URL:

- `download_iacacert_der(iacacert_url: Url) -> Result<Vec<u8>, ValidationError>`

This helper is intentionally separated from core validation so callers can choose online or offline flow.

### Planned stack
- `rustls-webpki` (webpki-based certificate path validation)
- `reqwest` with `rustls` backend (no OpenSSL)
- `rustls-tls-native-roots` so HTTPS uses native root trust (including Windows trust store)

### Validation flow (draft)
1. Parse `iacacert_der` and `x5chain` into X.509 certificate objects.
2. Build chain: leaf + intermediates, anchored by provided IACA root.
3. Validate:
   - signature chain
   - validity period
   - key usage / extended key usage required by spec (to be confirmed in implementation)
   - basic constraints and path length rules
4. Inspect CRL Distribution Points from `iacacert`.
5. If CRL URI exists:
   - download CRL
   - validate CRL issuer/signature/freshness as required by spec
   - confirm leaf certificate is not revoked (minimum requirement)

### CRL requirement notes
- Requirement target: leaf revocation check is mandatory when CRL info is present.
- Preferred behavior: follow Annex B.3.2 CRL validation example.
- Open technical check: confirm whether current `webpki` APIs can perform required CRL validation directly, or if supplemental X.509/CRL parsing/verification is needed.

### Output (proposed)
A typed result with explicit reasons:
- `Valid`
- `InvalidChain`
- `Expired`
- `Revoked`
- `CrlUnavailable`
- `NetworkError`
- `ParseError`
- `Unsupported` (for spec requirements not yet covered)

---

## #2 `mso_revocation_check`

### Goal
Implement MSO revocation logic based on section 12.3.6 using `VerifiedMso` and `iacacert`.

### Inputs
- `verified_mso: VerifiedMso`
- `iacacert_der: &[u8]` (DER-encoded IACA root certificate)

### Data source behavior (section 12.3.6.2)
1. Extract status endpoint URL from `Status` structure in MSO.
2. Access the URL using `reqwest`.
3. Determine certificate used for status response verification:
   - If certificate is included in MSO status info, use it.
   - Otherwise, use IACA certificate.

### Status formats
Both should be supported:
- `identifier_list`
- `status_list`

### Reuse expectation
- Certificate verification for status response should reuse `certificate_validation` as much as possible.
- Shared logic candidate: certificate chain + revocation verification utility module.

### Open design question
Difference in verification behavior between MSO-contained certificate and fallback IACA certificate must be clarified during implementation (especially trust model and chain expectations).

---

## Suggested crate structure (initial)

```text
mdoc_validation/
  README.md
  src/
    lib.rs
    certificate_validation.rs
    mso_revocation_check.rs
    fetch.rs
    error.rs
    types.rs
```

Potential public API sketch:

- `download_iacacert_der(iacacert_url) -> Result<Vec<u8>, ValidationError>`
- `validate_reader_auth_certificate(iacacert_der, x5chain, now) -> Result<CertificateValidationOutcome, ValidationError>`
- `check_mso_revocation(verified_mso, iacacert_der, now) -> Result<MsoRevocationOutcome, ValidationError>`

---

## Dependency notes

Planned dependencies (exact versions TBD):
- `reqwest` with features:
  - `rustls-tls`
  - `rustls-tls-native-roots`
- `rustls-webpki` / `webpki`
- X.509/CRL support crate if webpki-only path is insufficient
- `thiserror` for typed errors
- `tracing` for diagnostics (optional)

---

## Additional concerns to resolve before implementation

- **HTTP caching / freshness policy**: define how long downloaded CRL/status responses are reusable.
- **Clock source and skew handling**: define acceptable tolerance for cert/CRL validity checks.
- **Fail-open vs fail-closed policy**: especially for temporary network failures when revocation endpoint is required.
- **Large payload defense**: enforce strict max size for certificate, CRL, and status responses.
- **Content-type and encoding checks**: validate expected DER/CBOR formats before parsing.
- **Deterministic errors for integrators**: keep stable error categories for UI/logging and retry strategy.

---

## Security and robustness considerations

- Enforce HTTPS for external certificate/CRL/status fetches unless spec explicitly permits otherwise.
- Add request timeout and size limits for downloaded cert/CRL/status payloads.
- Handle malformed ASN.1/DER safely.
- Avoid soft-fail on revocation checks when CRL is required by policy.
- Ensure deterministic behavior in offline/error conditions with explicit error variants.

---

## Test plan (for implementation phase)

- Unit tests
  - Valid chain / invalid chain / expired leaf
  - CRL present + leaf revoked / not revoked
  - Missing or unreachable CRL endpoint
  - status_list and identifier_list parsing/verification
- Integration tests
  - Mock HTTP for iacacert/CRL/status endpoints
  - Certificate source selection behavior (MSO cert vs IACA fallback)
  - DER input validation for API boundary
- Cross-platform check
  - Verify HTTPS behavior with native roots on Windows environment

---

## Current scope of this task

This task only creates the folder and planning document. No production Rust implementation is included yet.
