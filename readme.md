# MPC Wallet

An educational MPC (Multi-Party Computation) wallet built in Go. The goal is to understand the cryptographic primitives behind threshold ECDSA wallets from the ground up.

## What it does

Sends Ethereum transactions where no single party ever holds the full private key. The key is split across N parties and any T+1 of them must collaborate to sign.

```
3 parties, threshold 2:
  Party 1 has share x1
  Party 2 has share x2     any 2 of 3 can sign
  Party 3 has share x3
```

## Architecture

```
Our packages (built from scratch)      tss-lib (used for signing only)
──────────────────────────────────     ──────────────────────────────
shamir   — secret sharing / Lagrange
pedersen — commitments
vss      — verifiable secret sharing
dkg      — distributed key generation
paillier — homomorphic encryption
mta      — multiplicative-to-additive
         │
         │  convertToTssLib()
         ▼
   LocalPartySaveData  ──────────────►  GG20 threshold signing
                                        (no key reconstruction)
```

### convertToTssLib mapping

| Our field | tss-lib field | Description |
|---|---|---|
| `DKGResult.FinalShare.Value` | `LocalSecrets.Xi` | Secret share scalar |
| share index (1, 2, 3…) | `LocalSecrets.ShareID` | Party identifier |
| `xi * G` per party | `BigXj` | Public key shares |
| `Σ λi * xi * G` | `ECDSAPub` | Group public key |
| `GeneratePreParamsWithContext` | `LocalPreParams` | Paillier + ZK range proof params |

The only part that uses tss-lib's own generator is the Paillier pre-params — tss-lib's GG20 signing rounds use its own `paillier.PrivateKey` type internally for the MtA steps, so we cannot swap our type in there. Everything else (key generation, share distribution, VSS verification, public key derivation) is our own code.

## Packages

| Package | What it does |
|---|---|
| `shamir` | Splits a secret into shares, reconstructs via Lagrange interpolation |
| `pedersen` | Pedersen commitments — commit to a value without revealing it |
| `vss` | Verifiable secret sharing — proves a share is valid without revealing the secret |
| `dkg` | Runs the full distributed key generation protocol (Round1 / Round2) |
| `paillier` | Paillier homomorphic encryption — `Enc(a) * Enc(b) = Enc(a+b)` |
| `mta` | Multiplicative-to-Additive conversion — used in threshold signing to compute `a*b = α + β` without either party learning the other's input |
| `threshold` | Wires our DKG into tss-lib's signing via `convertToTssLib` |
| `wallet` | Builds and broadcasts Ethereum transactions using the threshold signer |

## Usage

```go
// 3 parties, any 2 can sign (threshold = 1 means threshold+1 = 2 signers)
w, err := wallet.New(3, 1, "https://rpc.sepolia.org")

fmt.Println(w.Address()) // fund this address first

tx, err := w.SendTransaction(ctx,
    common.HexToAddress("0xRecipient..."),
    big.NewInt(1e18), // 1 ETH in wei
)
fmt.Println(tx.Hash())
```

```
go run .
```

## Why each primitive exists

**Shamir secret sharing** — splits the private key into N shares so no single party can steal the key.

**Pedersen commitments** — each party commits to their polynomial coefficients before revealing them, preventing a party from choosing their secret after seeing others'.

**VSS** — each party can verify their received share is consistent with the sender's commitment, detecting cheating.

**DKG** — combines VSS across all parties so the group secret is never known by anyone, not even during key generation.

**Paillier + MtA** — during signing, parties need to compute `k * x` (nonce times private key) without revealing either. MtA converts this multiplicative relationship into additive shares using Paillier encryption.

**tss-lib GG20** — the full threshold ECDSA signing protocol. Takes our DKG output (converted to its format) and produces a valid ECDSA signature without reconstructing the key.
