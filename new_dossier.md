  const dossierMarkdown = `# Technical Position Paper — Dual-Key Sovereign Validation System (DK-SVS)
**v2.5 Implementation-Accurate | 20 July 2026 | TRL 4**

---

## 1. Executive Summary
The Dual-Key Sovereign Validation System (DK-SVS) is an architectural model for privacy-preserving regulatory enforcement at the retail edge. As of July 2026, the Project Bilanx DK-SVS sandbox has achieved **Technology Readiness Level (TRL) 4 (lab validation)**. 

The current environment demonstrates a functional, dual-key cryptographic path where both keys undergo explicit server-side verification:
1. **Key 1 (Institutional Binding):** Validated via ECDSA P-256 over a strict payload structure.
2. **Key 2 (Age-Gate NIZKP):** Validated via Non-Interactive Zero-Knowledge Proofs (NIZKP) using Pedersen commitments and an 8-bit range proof (B2).

This document serves as an implementation-accurate representation of the current sandbox state. It explicitly supersedes previous versions that framed Key 1 as a local-only handshake and removes unevidenced performance or semantic claims.

---

## 2. Problem Statement
Traditional regulatory checks at the retail edge (e.g., age verification for restricted goods) require the exchange of Personally Identifiable Information (PII) or rely on visual inspection. This introduces GDPR liabilities, operational friction, and vulnerability to circumvention.

DK-SVS aims to decouple the proof of eligibility from the identity of the citizen, providing a Zero-PII validation path suitable for high-volume transactions, acting as a potential downstream consumer of eIDAS/EUDI identity assertions.

---

## 3. System Overview — Dual-Key Model
The core of the system is the Dual-Key orchestrator. Both keys must be validated for a transaction to proceed.

### 3.1 Key 1: Institutional Binding
Key 1 represents the user's registered device or credential binding.
- **Mechanism:** ECDSA P-256 signature over a specific challenge.
- **Validation Path:** The client transmits a \`DualKeyPayload\` to the server at \`POST /api/v1/dual-key/verify\`. The server performs real ECDSA P-256 verification.
- **Orchestration Constraint:** The orchestrator enforces a **fail-closed rule**. If Key 1 server verification fails or the payload is tampered with, the flow terminates immediately. Key 2 (Age-Gate) is never generated.

### 3.2 Key 2: Age-Gate NIZKP
Key 2 represents the specific semantic predicate (e.g., "Over 18").
- **Mechanism:** A Non-Interactive Zero-Knowledge Proof (NIZKP). Uses Pedersen commitments on NIST P-256 with a NUMS (Nothing Up My Sleeve) generator H, performing a B2 8-bit bit-decomposition range proof.
- **Validation Path:** The client generates a fixed 1355-byte binary proof. This is transmitted to the server at \`POST /api/v1/age-gate/verify\` for cryptographic verification.

---

## 4. Cryptographic Architecture

### 4.1 Key 1 (ECDSA)
- **Curve:** NIST P-256
- **Algorithm:** ECDSA with SHA-256
- **Format:** Raw IEEE P1363 (r‖s) signature encoding.

### 4.2 Key 2 (NIZKP Range Proof)
- **Curve:** NIST P-256 (\`@noble/curves\` implementation)
- **Commitment Scheme:** Pedersen commitments.
- **Range Proof Scheme:** B2 bit-decomposition (8-bit).
- **Proof Size:** Exactly 1355 bytes.

---

## 5. Runtime Architecture
1. **Initiation:** The client receives an institutional challenge (\`challengeId\`).
2. **Key 1 Execution:** The client signs the challenge and second factor hash using its local P-256 private key.
3. **Key 1 Server Verification:** The client sends the payload to \`POST /api/v1/dual-key/verify\`.
4. **Hard Gate:** If the server rejects Key 1, execution stops.
5. **Key 2 Execution:** If Key 1 is valid, the client generates the 1355-byte B2 range proof.
6. **Key 2 Server Verification:** The client sends the proof to \`POST /api/v1/age-gate/verify\`.
7. **Final Decision:** The orchestrator evaluates both server responses.

---

## 6. Wire Formats

### 6.1 DualKeyPayload (Key 1)
\`\`\`ts
interface DualKeyPayload {
  v: 1;
  challengeId: string;
  secondFactorHash: string;      // hex lowercase SHA-256
  userPublicKey: JsonWebKey;     // EC P-256 public only (no d)
  userSignature: string;         // base64url, no padding, raw P1363
  clientTs?: string;             // optional, NOT signed
}
\`\`\`
**Canonical Signed Message (UTF-8):** \`challengeId + ":" + secondFactorHash\`

### 6.2 B2 Binary Proof (Key 2)
- **Format:** Binary encoded payload.
- **Size:** Exactly 1355 bytes.

---

## 7. Security Properties — Honest Assessment

| Property | Status in Sandbox | Notes |
| :--- | :--- | :--- |
| **Zero-PII Transmission** | Verified | The server receives only public keys, hashes, signatures, and ZK proofs. No personal data is transmitted. |
| **Server-Side Authorization** | Verified | Both Key 1 and Key 2 require explicit cryptographic verification by the server endpoints. |
| **Fail-Closed Design** | Verified | The orchestrator terminates if Key 1 fails; invalid Key 1 payloads are caught (lab-validated via tamper test E6). |
| **Replay Protection** | Partial | \`challengeId\` prevents basic replay, but comprehensive nonce management and expiration are scope for higher TRLs. |
| **Hardware Security** | Not Evidenced | Keys are currently stored in browser software (IndexedDB/CryptoKey). No secure enclave or HSM integration is present. |

---

## 8. Performance & Measurement
Performance metrics are derived from the latest F4-class measurement campaign (N=30, 0 failures) running in the sandbox environment.

| Metric | Mean (approx) | Description |
| :--- | :--- | :--- |
| \`dualKey_ms\` | ~12 ms | Client-side Dual-Key (Key 1) execution time. |
| \`server_dual_key_verify_ms\`| ~6 ms | Server-side Key 1 ECDSA verification time. |
| \`prove_ms\` (B2) | ~285–300 ms | Client-side Key 2 (B2) proof generation time. |
| \`verify_ms\` / \`server_verify_ms\` | ~350 / ~344 ms | Server-side Key 2 (B2) proof verification time. |
| \`total_ms\` | ~650–680 ms | Full end-to-end orchestrated execution time. |
| \`proofByteLength\` | 1355 bytes | Fixed size of the Key 2 binary proof. |

*Note: Total validation time is currently ~650-680ms. The project makes no claim of sub-150ms full-path execution.*

---

## 9. Implementation Status & TRL

The sandbox operates at **TRL 4 (Technology validated in lab)**.

| Component | Status | TRL |
| :--- | :--- | :--- |
| Key 1 (Institutional Binding) | Lab-Validated (Client & Server) | 4 |
| Key 2 (Age-Gate ZKP) | Lab-Validated (Client & Server) | 4 |
| Orchestrator (Fail-Closed) | Lab-Validated | 4 |
| E2E Acceptance Harness | Passing (E1-E6) | 4 |
| eIDAS-Node / SAML 2.0 | Reference Architecture Only | 2 |
| EUDI Wallet / OpenID4VP | Target Architecture Only | 1 |
| Product Legitimacy / EMCS | Not Implemented | 1 |
| WASM / Native Acceleration | Not Implemented | 1 |

---

## 10. eIDAS / EUDI Positioning
The current sandbox **does not** integrate with a live eIDAS-Node or an EUDI Wallet.
- **eIDAS-Node 3.1.0** is considered a reference architecture for ingestion, but is not embedded in the runtime.
- **EUDI Wallet (OpenID4VP)** is the strategic target for the credential source, but no implementation currently exists in the lab.

---

## 11. Risks & Limitations
1. **Performance Overhead:** JavaScript-based proof generation and verification (~650ms total) is functional for labs but may be too slow for high-throughput physical POS environments.
2. **Software Key Storage:** Browser-based key storage is vulnerable to extraction if the host device is compromised.
3. **Missing Semantic Predicates:** The system only demonstrates an age-gate. Complex predicates (e.g., AEO, EMVS, DPP) are researched but not implemented.

---

## 12. Explicit Non-Claims
To maintain transparency and auditability, the project explicitly disclaims the following:
- We **do not** claim TRL 6 or 7.
- We **do not** claim full-path execution under 150ms.
- We **do not** claim implementation of product-legitimacy, fiscal-stamp, or EMCS validation logic.
- We **do not** claim production-ready integration with European digital identity infrastructure (eIDAS/EUDI).
- We **do not** claim national-scale or POS production deployment readiness.

---

## 13. Roadmap
- **Near-term:** Solidify lab metrics, document error conditions, and optimize Javascript cryptographic overhead where possible.
- **Deferred:** Implementation of semantic predicates (AEO, DPP, etc.), EUDI Wallet / OpenID4VP integration, and WASM native acceleration.

---

## 14. Compliance Checklist
- [x] Dual-Key orchestration enforces a fail-closed constraint.
- [x] Key 1 is server-verified via ECDSA P-256.
- [x] Key 2 is server-verified via B2 Range Proof (1355 bytes).
- [x] TRL 4 boundaries strictly observed.
- [x] Zero-PII transmission confirmed in payloads.
- [x] Performance baseline documented (N=30, ~650ms E2E).

---
*End of Technical Position Paper v2.5*
`;
