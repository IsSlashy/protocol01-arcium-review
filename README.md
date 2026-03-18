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
├── Cargo.toml                  # Dependencies (anchor 0.32.1, arcium 0.8.5)
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

## Questions for Arcium Team

### 1. MXE State Persistence
We use `Enc<Mxe, T>` for state that needs to persist between calls:
- `balance_audit` accumulates into `Enc<Mxe, AuditAccumulator>`
- `private_vote` accumulates into `Enc<Mxe, VoteTally>`
- `register_viewing_key` stores into `Enc<Mxe, ViewingKeyState>`

**Question:** Does `Enc<Mxe, T>` state persist across separate computation requests? Or only within a single computation session? If it doesn't persist, our accumulation pattern breaks.

### 2. Comparison Cost Optimization
`private_vote` does 8 equality comparisons per call (`opt == 0` through `opt == 7`). We added `private_vote_binary` (2 comparisons) as an optimization for yes/no votes.

**Question:** Is there a recommended Arcis pattern for conditional accumulation without equality comparisons? (e.g., arithmetic selector, lookup table, or boolean masking)

### 3. On-Chain Account Access from MPC
`private_lookup` is a stub — it echoes input instead of reading the on-chain registry. The real implementation needs to read a Solana PDA from within the MPC circuit.

**Question:** How do we pass an on-chain account reference to an Arcis circuit so the MPC can read its data? Is this via `ArgBuilder` remaining accounts, or is there a dedicated API?

### 4. SHA3 in MPC — Cost Considerations
`nullifier_commit` and `stealth_scan_single` both use `SHA3_256::new().digest()`. SHA3 inside MPC involves many rounds of non-linear operations.

**Question:** Is SHA3 the recommended hash for MPC circuits, or would a different hash (e.g., Poseidon, MiMC) be significantly cheaper in terms of ACUs?

### 5. General Architecture Review
We'd appreciate a review of the overall circuit design for:
- Red flags (security, correctness)
- Unnecessary complexity
- Opportunities to batch or merge circuits
- Any Arcis anti-patterns we should avoid

## Devnet Program IDs

| Program | Address |
|---------|---------|
| p01_arcium | `FH1JiQRUhKP1ARqWw6P5aXsqhLt9DPfbg89gqLV2TLPT` |

## Tech Stack

- Anchor 0.32.1 / arcium-anchor 0.8.5
- Arcis 0.8.5 (encrypted instructions)
- @arcium-hq/client 0.8.5
- Solana devnet (Agave 2.2.14)

## Contact

**Volta Team** (solo dev)
Building a privacy layer for Solana — ZK-SNARKs (Groth16), stealth addresses (ECDH), confidential balances, and Arcium MPC for threshold operations.
