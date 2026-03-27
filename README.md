# Protocol 01 — Arcium MPC Integration (Review)

Privacy protocol on Solana using Arcium gMPC for confidential computation. This repo contains **only** the Arcium integration layer — the full protocol is closed-source.

**Deployed on devnet:** `FH1JiQRUhKP1ARqWw6P5aXsqhLt9DPfbg89gqLV2TLPT`
**MXE Account:** `3EzPEVpUaeaJJyMqi4FB8Ch3GQ6N5bxxZZQ1ECtibT4y`
**Cluster:** 456 (devnet) | Backend: Cerberus
**All 11 comp_defs initialized and operational on devnet.**

## Architecture

```
User → encrypt(data) → Solana TX → p01_arcium program → CPI → Arcium MXE
                                                                    ↓
                                                              ARX Cluster (MPC)
                                                                    ↓
                                                            Callback → on-chain result
```

## 6 Use Cases (11 Circuits)

### UC1: Confidential Relay (`threshold_decrypt`)
Encrypted transaction → MPC threshold decrypts → executes on-chain.
No single relayer sees the plaintext TX. Callback emits blake3 hash only.

### UC2: Anonymous Registry Lookup (`private_lookup`)
User encrypts target wallet → MPC reads on-chain registry → re-encrypts result for querier.
RPC node never sees who you're looking up. Currently a proof-of-concept stub.

### UC3: Hidden Nullifier Commitment (`nullifier_commit`)
Encrypted nullifier → MPC computes SHA3-256 commitment → returns hash on-chain.
Nullifier stays secret, only the commitment is public. Prevents double-spend without revealing which note was spent.

**v0.9.5 fix:** Nullifier encryption now splits 32-byte nullifier into 4 × u64 chunks (each bounded within the 254-bit Poseidon field). Previously, a single 256-bit bigint overflowed the field in ~75% of cases, causing silent MPC failures.

### UC4: Confidential Balance Audit (`balance_audit` + `finalize_audit`)
Users submit encrypted balances → MPC accumulates → authority reveals only the total.
Individual amounts never disclosed. Uses `Enc<Mxe, AuditAccumulator>` for cross-call state.

### UC5: Threshold Stealth Scanning (`register_viewing_key` + `stealth_scan_single`)
Viewing key stored in MXE state (threshold-sharded). MPC computes SHA3(viewing_key || ephemeral_key) and matches view-tags without reconstructing the viewing key. Single-announcement scanning with 1 comparison.

### UC6: Private Governance Voting (`private_vote` + `finalize_tally`)
Encrypted votes accumulated in MXE state. 8-option support with conditional addition.
Only the final tally is revealed after deadline. Authority + deadline checks on-chain.

**UC6b (optimized):** `private_vote_binary` + `finalize_tally_binary` — 2 comparisons instead of 8 for yes/no votes (75% fewer MPC comparisons).

## File Structure

```
programs/p01_arcium/
├── encrypted-ixs/src/lib.rs    # Arcis MPC circuits (11 circuits, ~416 lines)
├── src/lib.rs                  # Anchor program (queue, callbacks, accounts, ~1700 lines)
├── Cargo.toml                  # Dependencies (anchor 0.32.1, arcium 0.9.0)
├── Arcium.toml                 # Cluster config (devnet 456, mainnet 2026)
└── Anchor.toml                 # Program ID

sdk/src/
├── client.ts                   # ArciumClient wrapper (encrypt, queue, finalize)
├── governance/index.ts         # castVote, castBinaryVote, finalizeTally
├── relay/index.ts              # submitConfidentialRelayJob
├── registry/index.ts           # privateLookup
├── nullifier/index.ts          # commitNullifier
├── audit/index.ts              # submitBalanceForAudit, finalizeAudit
└── stealth/index.ts            # registerViewingKey, scanAnnouncements

build/
├── *.idarc                     # Circuit interface descriptors (input/output schemas)
└── *.ts                        # Generated TypeScript types for each circuit

tests/
└── p01-arcium.test.ts          # Integration tests (init comp_defs, all 6 UCs)
```

## Circuit Costs (ACUs)

| Circuit | ACUs | Comparisons | SHA3 | MXE State |
|---------|------|-------------|------|-----------|
| `balance_audit` | 530M | 0 | No | Write (accumulator) |
| `finalize_audit` | 144M | 0 | No | Read (accumulator) |
| `private_vote` | 628M | 8 | No | Write (8-option tally) |
| `finalize_tally` | 177M | 0 | No | Read (8-option tally) |
| `private_vote_binary` | 554M | 2 | No | Write (2-option tally) |
| `finalize_tally_binary` | 145M | 0 | No | Read (2-option tally) |
| `nullifier_commit` | 1,012M | 0 | Yes (32B) | None |
| `private_lookup` | 512M | 0 | No | None (stub) |
| `register_viewing_key` | 769M | 0 | No | Write (32B key) |
| `stealth_scan_single` | 1,216M | 1 | Yes (64B) | Read (32B key) |
| `threshold_decrypt` | 466M | 0 | No | None |

Most expensive: `stealth_scan_single` (SHA3-256 over 64 bytes + 1 comparison).
Cheapest: `finalize_audit` / `finalize_tally_binary` (just reveals).

## Integration Status (v0.9.5)

| Use Case | Status | Notes |
|----------|--------|-------|
| UC1 Confidential Relay | Operational | Threshold decrypt + callback working on devnet |
| UC2 Anonymous Lookup | Stub | Needs on-chain account access from MPC (see Q2 below) |
| UC3 Hidden Nullifier | **Fixed** | Was failing ~75% — nullifier split into 4×u64 chunks for Poseidon field |
| UC4 Balance Audit | Operational | Accumulator pattern with `Enc<Mxe, T>` |
| UC5 Stealth Scanning | Operational | Viewing key threshold-sharded, view-tag matching |
| UC6 Private Voting | Operational | Binary variant (2 comparisons) deployed alongside 8-option |

### What's Working in Production
- **Shield**: Stealth intermediary hides wallet on-chain → pool deposit via ZK program
- **Unshield**: Stealth signer (fee payer) + stealth ECDH recipient → wallet never visible
- **Nullifier**: 4×u64 chunk encryption → MPC SHA3 commitment (when MPC available, graceful fallback to standard PDA)
- **Sweep**: Delayed auto-sweep (3-7s jitter) from stealth recipient to real wallet
- **Bluetooth note transfer**: Off-chain handoff, zero on-chain trace

## Open Questions for Arcium Team

### 1. On-Chain Account Access from MPC
`private_lookup` needs to read a Solana PDA (registry) from within the MPC circuit. Currently stubbed (echoes input).

**Question:** How do we pass an on-chain account reference to an Arcis circuit? Via `ArgBuilder` remaining accounts, or a dedicated API?

### 2. Hash Function Cost
`nullifier_commit` and `stealth_scan_single` use `SHA3_256::new().digest()` inside MPC. SHA3 is expensive in MPC due to non-linear rounds.

**Question:** Would Poseidon or MiMC be significantly cheaper in ACUs while maintaining security for our use case?

### 3. Architecture Review
We'd appreciate a review of the overall circuit design for:
- Security red flags
- Opportunities to batch or merge circuits
- Any Arcis anti-patterns we should avoid

## Devnet Program IDs

| Program | Address |
|---------|---------|
| p01_arcium | `FH1JiQRUhKP1ARqWw6P5aXsqhLt9DPfbg89gqLV2TLPT` |

## Tech Stack

- Anchor 0.32.1 / arcium-anchor 0.9.0
- Arcis 0.9.0 (encrypted instructions)
- @arcium-hq/client 0.9.0
- Solana devnet (Agave 2.2.14)

## v0.9.5 Privacy Improvements

- **Full stealth unshield**: Both signer and recipient are ephemeral on-chain. User wallet never appears in the unshield transaction.
- **Stealth ECDH recipient**: Pool sends to a one-time address derived from the user's meta-address (X25519 + ML-KEM-768 hybrid).
- **MPC nullifier fix**: 32-byte nullifier split into 4 × u64 chunks to fit the 254-bit Poseidon field. Fixes ~75% silent failure rate.
- **Timing decorrelation**: Random jitter (1-7s) between funding, unshield, and sweep transactions.

## Contact

**Volta Team** (solo dev)
Privacy layer for Solana — ZK-SNARKs (Groth16), STARK proofs (quantum-resistant), stealth addresses (ECDH + ML-KEM-768), and Arcium gMPC for confidential computation.

- **12 Solana programs**, 6 Circom circuits, 6 STARK AIRs, 3 client apps
- **Mobile**: Android APK with on-device ZK proving (WebView WASM)
- **Devnet**: All programs deployed and operational
