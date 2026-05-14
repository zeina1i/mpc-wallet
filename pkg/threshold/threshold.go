package threshold

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	gocrypto "github.com/bnb-chain/tss-lib/v2/crypto"
	tsspaillier "github.com/bnb-chain/tss-lib/v2/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"

	"github.com/zeina1i/mpc-wallet/pkg/dkg"
	"github.com/zeina1i/mpc-wallet/pkg/shamir"
)

// Keygen runs our own DKG to produce ECDSA key shares, then converts them into
// tss-lib's LocalPartySaveData so that tss-lib can sign without ever
// reconstructing the private key.
//
// Our packages in use:
//   - dkg      — distributed key generation (Round1 / Round2)
//   - vss      — verifiable secret sharing (inside dkg)
//   - pedersen — commitments in DKG broadcasts (inside dkg)
//   - shamir   — Lagrange coefficients for the group public key
func Keygen(partyCount, threshold int) ([]keygen.LocalPartySaveData, error) {
	results, err := runDKG(partyCount, threshold)
	if err != nil {
		return nil, err
	}

	// Generate tss-lib pre-params (Paillier keys + ZK range-proof params) per
	// party. Our paillier package uses the same maths but different Go types;
	// tss-lib's MtA inside signing requires its own paillier.PrivateKey.
	preParams := make([]keygen.LocalPreParams, partyCount)
	for i := 0; i < partyCount; i++ {
		pp, err := keygen.GeneratePreParamsWithContext(context.Background())
		if err != nil {
			return nil, fmt.Errorf("pre-params party %d: %w", i, err)
		}
		preParams[i] = *pp
	}

	return convertToTssLib(results, preParams)
}

// Sign runs tss-lib's GG20 threshold signing over the key shares produced by
// our DKG. The private key is never reconstructed.
func Sign(msgHash []byte, keys []keygen.LocalPartySaveData, threshold int) (r, s *big.Int, err error) {
	signerCount := threshold + 1

	// Party IDs must have Key == ShareID so that BuildLocalSaveDataSubset can
	// match each signer's PartyID.Key against the Ks array in LocalPartySaveData.
	unsorted := make(tss.UnSortedPartyIDs, signerCount)
	for i := 0; i < signerCount; i++ {
		id := fmt.Sprintf("%d", i+1)
		unsorted[i] = tss.NewPartyID(id, id, keys[i].ShareID)
	}
	partyIDs := tss.SortPartyIDs(unsorted)
	ctx := tss.NewPeerContext(partyIDs)
	m := new(big.Int).SetBytes(msgHash)

	errCh := make(chan *tss.Error, signerCount)
	outCh := make(chan tss.Message, signerCount*signerCount)
	endCh := make(chan *common.SignatureData, signerCount)

	parties := make([]tss.Party, signerCount)
	for i, id := range partyIDs {
		params := tss.NewParameters(tss.S256(), ctx, id, signerCount, threshold)
		parties[i] = signing.NewLocalParty(m, params, keys[i], outCh, endCh)
		go func(p tss.Party) {
			if tssErr := p.Start(); tssErr != nil {
				errCh <- tssErr
			}
		}(parties[i])
	}

	for {
		select {
		case tssErr := <-errCh:
			return nil, nil, fmt.Errorf("sign: %v", tssErr)
		case msg := <-outCh:
			route(msg, parties, errCh)
		case sig := <-endCh:
			return new(big.Int).SetBytes(sig.R), new(big.Int).SetBytes(sig.S), nil
		}
	}
}

// runDKG executes our DKG protocol and returns one DKGResult per party.
func runDKG(partyCount, threshold int) ([]dkg.DKGResult, error) {
	seed := []byte("shared-pedersen-seed")

	participants := make([]*dkg.ParticipantImpl, partyCount)
	for i := 0; i < partyCount; i++ {
		p, err := dkg.NewParticipant(dkg.ParticipantID(i+1), threshold, partyCount, seed)
		if err != nil {
			return nil, fmt.Errorf("create participant %d: %w", i+1, err)
		}
		participants[i] = p
	}

	broadcasts := make([]*dkg.Round1Broadcast, partyCount)
	allShares := make([]map[dkg.ParticipantID]*dkg.Round1Share, partyCount)
	for i, p := range participants {
		bc, shares, err := p.Round1()
		if err != nil {
			return nil, fmt.Errorf("participant %d round1: %w", i+1, err)
		}
		broadcasts[i] = bc
		allShares[i] = shares
	}

	for _, p := range participants {
		for _, bc := range broadcasts {
			if bc.SenderID == p.GetID() {
				continue
			}
			if err := p.ProcessBroadcast(bc); err != nil {
				return nil, fmt.Errorf("participant %d process broadcast: %w", p.GetID(), err)
			}
		}
		for senderIdx, shares := range allShares {
			if dkg.ParticipantID(senderIdx+1) == p.GetID() {
				continue
			}
			if err := p.ProcessShare(shares[p.GetID()]); err != nil {
				return nil, fmt.Errorf("participant %d process share: %w", p.GetID(), err)
			}
		}
	}

	results := make([]dkg.DKGResult, partyCount)
	for i, p := range participants {
		res, err := p.Round2()
		if err != nil {
			return nil, fmt.Errorf("participant %d round2: %w", i+1, err)
		}
		results[i] = *res
	}
	return results, nil
}

// convertToTssLib maps our DKGResult into tss-lib's LocalPartySaveData.
//
// Field mapping:
//
//	DKGResult.FinalShare.Value  → LocalSecrets.Xi       secret share scalar
//	share index (1, 2, 3 …)    → LocalSecrets.ShareID  party identifier
//	xi * G  (each party)       → BigXj                 public share points
//	Σ λi * xi * G              → ECDSAPub              group public key
//	tss-lib pre-params          → LocalPreParams        Paillier + ZK params
func convertToTssLib(
	results []dkg.DKGResult,
	preParams []keygen.LocalPreParams,
) ([]keygen.LocalPartySaveData, error) {
	n := len(results)
	curve := tss.S256()
	q := shamir.Secp256k1Order()

	// BigXj[i] = xi * G  (public key share for party i)
	bigXj := make([]*gocrypto.ECPoint, n)
	ks := make([]*big.Int, n)
	for i, res := range results {
		bx, by := curve.ScalarBaseMult(res.FinalShare.Value.Bytes())
		pt, err := gocrypto.NewECPoint(curve, bx, by)
		if err != nil {
			return nil, fmt.Errorf("party %d pubkey share: %w", i, err)
		}
		bigXj[i] = pt
		ks[i] = big.NewInt(int64(res.FinalShare.Index))
	}

	// ECDSAPub = Σ λi(0) * xi * G — Lagrange-weighted sum, no secret needed
	ecdsaPub, err := groupPublicKey(results, bigXj, q, curve)
	if err != nil {
		return nil, fmt.Errorf("group public key: %w", err)
	}

	paillierPKs := make([]*tsspaillier.PublicKey, n)
	ntildej := make([]*big.Int, n)
	h1j := make([]*big.Int, n)
	h2j := make([]*big.Int, n)
	for i, pp := range preParams {
		paillierPKs[i] = &pp.PaillierSK.PublicKey
		ntildej[i] = pp.NTildei
		h1j[i] = pp.H1i
		h2j[i] = pp.H2i
	}

	saves := make([]keygen.LocalPartySaveData, n)
	for i := range results {
		saves[i] = keygen.LocalPartySaveData{
			LocalPreParams: preParams[i],
			LocalSecrets: keygen.LocalSecrets{
				Xi:      results[i].FinalShare.Value,
				ShareID: ks[i],
			},
			Ks:          ks,
			NTildej:     ntildej,
			H1j:         h1j,
			H2j:         h2j,
			BigXj:       bigXj,
			PaillierPKs: paillierPKs,
			ECDSAPub:    ecdsaPub,
		}
	}
	return saves, nil
}

// groupPublicKey computes Σ λi(0) * BigXj[i] using Lagrange coefficients.
// This is the group ECDSA public key — requires no secret values.
func groupPublicKey(results []dkg.DKGResult, bigXj []*gocrypto.ECPoint, q *big.Int, curve elliptic.Curve) (*gocrypto.ECPoint, error) {
	indices := make([]*big.Int, len(results))
	for i, r := range results {
		indices[i] = big.NewInt(int64(r.FinalShare.Index))
	}

	var sumX, sumY *big.Int
	for i := range results {
		lambda := lagrangeCoeff(indices[i], indices, q)
		lx, ly := curve.ScalarMult(bigXj[i].X(), bigXj[i].Y(), lambda.Bytes())
		if sumX == nil {
			sumX, sumY = lx, ly
		} else {
			sumX, sumY = curve.Add(sumX, sumY, lx, ly)
		}
	}
	return gocrypto.NewECPoint(curve, sumX, sumY)
}

// lagrangeCoeff computes λi(0) = Π_{j≠i} (-xj) / (xi - xj)  mod q
func lagrangeCoeff(xi *big.Int, xs []*big.Int, q *big.Int) *big.Int {
	num := big.NewInt(1)
	den := big.NewInt(1)
	for _, xj := range xs {
		if xj.Cmp(xi) == 0 {
			continue
		}
		num.Mul(num, new(big.Int).Neg(xj))
		num.Mod(num, q)
		den.Mul(den, new(big.Int).Sub(xi, xj))
		den.Mod(den, q)
	}
	return new(big.Int).Mod(new(big.Int).Mul(num, new(big.Int).ModInverse(den, q)), q)
}

func route(msg tss.Message, parties []tss.Party, errCh chan<- *tss.Error) {
	dest := msg.GetTo()
	if dest == nil {
		for _, p := range parties {
			if p.PartyID().Index == msg.GetFrom().Index {
				continue
			}
			go deliver(p, msg, errCh)
		}
	} else {
		go deliver(parties[dest[0].Index], msg, errCh)
	}
}

func deliver(p tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- p.WrapError(err)
		return
	}
	parsed, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		errCh <- p.WrapError(err)
		return
	}
	if _, tssErr := p.Update(parsed); tssErr != nil {
		errCh <- tssErr
	}
}
