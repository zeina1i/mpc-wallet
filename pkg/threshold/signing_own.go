package threshold

// SignOwn implements simplified threshold ECDSA using our own pkg/paillier
// and pkg/mta instead of tss-lib's internal MtA.
//
// No ZK range proofs — educational only.
//
// Protocol:
//   Round 1 — each party i generates ki (nonce), γi (blinding), Paillier keypair
//   Round 2 — MtA(ki, γj) for all pairs → δi  s.t. Σδi = k*γ
//   Round 3 — MtA(ki, λj*xj) for all pairs → σi  s.t. Σσi = k*x
//              (λj are Lagrange coefficients so that Σλj*xj = x, the private key)
//   Round 4 — R = (Σδi)⁻¹ * Σ(γi*G) = k⁻¹*G,  r = R.x mod q
//   Round 5 — si = ki*H(m) + r*σi,  s = Σsi = k*(H(m)+r*x)

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/zeina1i/mpc-wallet/pkg/mta"
	"github.com/zeina1i/mpc-wallet/pkg/paillier"
	"github.com/zeina1i/mpc-wallet/pkg/shamir"
)

// SignOwn produces a threshold ECDSA signature using our own MtA.
// shares[i] is the xi value (FinalShare.Value from DKG) for party i.
// Indices are assumed to be 1, 2, ..., n matching the DKG output.
func SignOwn(msgHash []byte, shares []*big.Int) (r, s *big.Int, err error) {
	q := shamir.Secp256k1Order()
	curve := tss.S256()
	n := len(shares)

	// Lagrange coefficients λi(0) for the signing party set with indices [1..n]
	// so that Σ λi * xi = x (the group private key)
	indices := make([]*big.Int, n)
	for i := range indices {
		indices[i] = big.NewInt(int64(i + 1))
	}
	lambdas := make([]*big.Int, n)
	for i := range lambdas {
		lambdas[i] = lagrangeCoeff(indices[i], indices, q)
	}

	// --- Round 1: each party generates ki, γi, and a Paillier keypair ---
	type party struct {
		xi     *big.Int
		ki     *big.Int
		gammai *big.Int
		pub    *paillier.PublicKey
		priv   *paillier.PrivateKey
	}

	parties := make([]party, n)
	for i := 0; i < n; i++ {
		ki, err := rand.Int(rand.Reader, q)
		if err != nil {
			return nil, nil, fmt.Errorf("party %d nonce: %w", i, err)
		}
		gammai, err := rand.Int(rand.Reader, q)
		if err != nil {
			return nil, nil, fmt.Errorf("party %d blinding: %w", i, err)
		}
		pub, priv, err := paillier.GenerateKeyPair(1024) // N >> q² ≈ 2^512
		if err != nil {
			return nil, nil, fmt.Errorf("party %d paillier: %w", i, err)
		}
		parties[i] = party{xi: shares[i], ki: ki, gammai: gammai, pub: pub, priv: priv}
	}

	// --- Round 2: MtA(ki, γj) → δi  s.t. Σδi = k*γ ---
	delta := make([]*big.Int, n)
	for i := range parties {
		delta[i] = new(big.Int).Mod(new(big.Int).Mul(parties[i].ki, parties[i].gammai), q)
	}
	for i := range parties {
		for j := range parties {
			if i == j {
				continue
			}
			alpha, beta, err := runMtA(parties[i].pub, parties[i].priv, parties[i].ki, parties[j].gammai, q)
			if err != nil {
				return nil, nil, fmt.Errorf("mta δ (%d,%d): %w", i, j, err)
			}
			delta[i] = new(big.Int).Mod(new(big.Int).Add(delta[i], alpha), q)
			delta[j] = new(big.Int).Mod(new(big.Int).Add(delta[j], beta), q)
		}
	}

	// --- Round 3: MtA(ki, λj*xj) → σi  s.t. Σσi = k*x ---
	// Bob uses λj*xj so the MtA accumulates the Lagrange-weighted key shares.
	sigma := make([]*big.Int, n)
	for i := range parties {
		// ki * λi * xi (own term, already Lagrange-weighted)
		sigma[i] = new(big.Int).Mul(parties[i].ki, new(big.Int).Mul(lambdas[i], parties[i].xi))
		sigma[i].Mod(sigma[i], q)
	}
	for i := range parties {
		for j := range parties {
			if i == j {
				continue
			}
			// Bob j contributes λj * xj
			xjWeighted := new(big.Int).Mod(new(big.Int).Mul(lambdas[j], parties[j].xi), q)
			mu, nu, err := runMtA(parties[i].pub, parties[i].priv, parties[i].ki, xjWeighted, q)
			if err != nil {
				return nil, nil, fmt.Errorf("mta σ (%d,%d): %w", i, j, err)
			}
			sigma[i] = new(big.Int).Mod(new(big.Int).Add(sigma[i], mu), q)
			sigma[j] = new(big.Int).Mod(new(big.Int).Add(sigma[j], nu), q)
		}
	}

	// --- Round 4: R = δ⁻¹ * Γ = k⁻¹*G,  r = R.x ---
	var gammaGx, gammaGy *big.Int
	for _, p := range parties {
		gx, gy := curve.ScalarBaseMult(p.gammai.Bytes())
		if gammaGx == nil {
			gammaGx, gammaGy = gx, gy
		} else {
			gammaGx, gammaGy = curve.Add(gammaGx, gammaGy, gx, gy)
		}
	}

	deltaSum := new(big.Int)
	for _, d := range delta {
		deltaSum.Add(deltaSum, d)
	}
	deltaSum.Mod(deltaSum, q)

	deltaInv := new(big.Int).ModInverse(deltaSum, q)
	Rx, _ := curve.ScalarMult(gammaGx, gammaGy, deltaInv.Bytes())
	r = new(big.Int).Mod(Rx, q)

	// --- Round 5: s = Σ(ki*H(m) + r*σi) = k*(H(m) + r*x) ---
	m := new(big.Int).Mod(new(big.Int).SetBytes(msgHash), q)

	s = new(big.Int)
	for i := range parties {
		si := new(big.Int).Add(
			new(big.Int).Mul(parties[i].ki, m),
			new(big.Int).Mul(r, sigma[i]),
		)
		s.Add(s, si)
	}
	s.Mod(s, q)

	return r, s, nil
}

// runMtA runs one MtA instance using our pkg/mta.
// Returns (α, β) s.t. α + β = a*b mod q.
func runMtA(pub *paillier.PublicKey, priv *paillier.PrivateKey, a, b, q *big.Int) (alpha, beta *big.Int, err error) {
	cA, err := mta.Step1Alice(pub, a)
	if err != nil {
		return nil, nil, err
	}
	bobOut, err := mta.Step2Bob(pub, cA, b, q)
	if err != nil {
		return nil, nil, err
	}
	aliceOut, err := mta.Step3Alice(priv, bobOut, q)
	if err != nil {
		return nil, nil, err
	}
	return aliceOut.Alpha, bobOut.Beta, nil
}
