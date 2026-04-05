package vss

import (
	"math/big"
	"testing"

	"github.com/zeina1i/mpc-wallet/pkg/pedersen"
)

// buildVerifierFixture creates a minimal 2-of-3 Pedersen VSS setup manually so
// the tests are self-contained and don't depend on the dealer implementation.
//
// Polynomial:  f(x) = secret + a1·x          (mod N)
// Blinding:    g(x) = r0    + r1·x            (mod N)
// Commitments: C0 = secret·G + r0·H,  C1 = a1·G + r1·H
// Share i:     Value = f(i), BlindingValue = g(i)
func buildVerifierFixture(t *testing.T) (params *Params, commitments []*Commitment, shares []*Share) {
	t.Helper()
	params = newTestParams()
	curve := params.Curve
	N := params.N

	secret := big.NewInt(42)
	a1 := big.NewInt(7)
	r0 := big.NewInt(13)
	r1 := big.NewInt(5)

	pImpl := pedersen.Impl{}
	ps := &pedersen.Params{
		G: &pedersen.Point{X: params.G.X, Y: params.G.Y},
		H: &pedersen.Point{X: params.H.X, Y: params.H.Y},
	}

	c0, _, _ := pImpl.Commit(ps, secret, r0.Bytes())
	c1, _, _ := pImpl.Commit(ps, a1, r1.Bytes())
	commitments = []*Commitment{
		{C: &Point{X: c0.Point.X, Y: c0.Point.Y}},
		{C: &Point{X: c1.Point.X, Y: c1.Point.Y}},
	}

	// Evaluate f(i) and g(i) for participants 1, 2, 3
	shares = make([]*Share, 3)
	for i := 1; i <= 3; i++ {
		x := big.NewInt(int64(i))

		// f(i) = secret + a1·i mod N
		fi := new(big.Int).Mul(a1, x)
		fi.Add(fi, secret)
		fi.Mod(fi, N)

		// g(i) = r0 + r1·i mod N
		gi := new(big.Int).Mul(r1, x)
		gi.Add(gi, r0)
		gi.Mod(gi, N)

		shares[i-1] = &Share{Index: i, Value: fi, BlindingValue: gi}
	}

	_ = curve
	return
}

func TestNewVerifier_ReturnsVerifier(t *testing.T) {
	params := newTestParams()
	commitments := []*Commitment{{C: &Point{X: big.NewInt(1), Y: big.NewInt(2)}}}

	v, err := NewVerifier(params, commitments)
	if err != nil {
		t.Fatalf("NewVerifier returned error: %v", err)
	}
	if v == nil {
		t.Fatal("NewVerifier returned nil")
	}
}

func TestGetCommitments_ReturnsSameCommitments(t *testing.T) {
	params, commitments, _ := buildVerifierFixture(t)
	v, _ := NewVerifier(params, commitments)

	got := v.GetCommitments()
	if len(got) != len(commitments) {
		t.Fatalf("len(commitments) = %d, want %d", len(got), len(commitments))
	}
	for i := range commitments {
		if got[i] != commitments[i] {
			t.Errorf("commitment[%d] pointer mismatch", i)
		}
	}
}

func TestGetMyShare_NilBeforeAccept(t *testing.T) {
	params, commitments, _ := buildVerifierFixture(t)
	v, _ := NewVerifier(params, commitments)

	if v.GetMyShare() != nil {
		t.Error("GetMyShare should be nil before AcceptShare")
	}
}

func TestVerifyShare_ValidShare(t *testing.T) {
	params, commitments, shares := buildVerifierFixture(t)
	v, _ := NewVerifier(params, commitments)

	for _, s := range shares {
		if !v.VerifyShare(s) {
			t.Errorf("VerifyShare failed for valid share at index %d", s.Index)
		}
	}
}

func TestVerifyShare_TamperedValue(t *testing.T) {
	params, commitments, shares := buildVerifierFixture(t)
	v, _ := NewVerifier(params, commitments)

	tampered := &Share{
		Index:         shares[0].Index,
		Value:         new(big.Int).Add(shares[0].Value, big.NewInt(1)),
		BlindingValue: shares[0].BlindingValue,
	}
	if v.VerifyShare(tampered) {
		t.Error("VerifyShare should fail for tampered share value")
	}
}

func TestVerifyShare_TamperedBlinding(t *testing.T) {
	params, commitments, shares := buildVerifierFixture(t)
	v, _ := NewVerifier(params, commitments)

	tampered := &Share{
		Index:         shares[0].Index,
		Value:         shares[0].Value,
		BlindingValue: new(big.Int).Add(shares[0].BlindingValue, big.NewInt(1)),
	}
	if v.VerifyShare(tampered) {
		t.Error("VerifyShare should fail for tampered blinding value")
	}
}

func TestVerifyShare_WrongIndex(t *testing.T) {
	params, commitments, shares := buildVerifierFixture(t)
	v, _ := NewVerifier(params, commitments)

	// Share values for index 1 must not verify at index 2
	wrongIndex := &Share{
		Index:         2,
		Value:         shares[0].Value,
		BlindingValue: shares[0].BlindingValue,
	}
	if v.VerifyShare(wrongIndex) {
		t.Error("VerifyShare should fail when index does not match the share values")
	}
}

func TestAcceptShare_ValidShareStored(t *testing.T) {
	params, commitments, shares := buildVerifierFixture(t)
	v, _ := NewVerifier(params, commitments)

	if err := v.AcceptShare(shares[0]); err != nil {
		t.Fatalf("AcceptShare failed for valid share: %v", err)
	}
	if v.GetMyShare() != shares[0] {
		t.Error("GetMyShare did not return the accepted share")
	}
}

func TestAcceptShare_InvalidShareReturnsError(t *testing.T) {
	params, commitments, shares := buildVerifierFixture(t)
	v, _ := NewVerifier(params, commitments)

	bad := &Share{
		Index:         shares[0].Index,
		Value:         big.NewInt(9999),
		BlindingValue: big.NewInt(9999),
	}
	if err := v.AcceptShare(bad); err == nil {
		t.Error("AcceptShare should return error for invalid share")
	}
	if v.GetMyShare() != nil {
		t.Error("share should not be stored after failed AcceptShare")
	}
}

func TestGetPublicKey_MatchesC0(t *testing.T) {
	params, commitments, _ := buildVerifierFixture(t)
	v, _ := NewVerifier(params, commitments)

	pk := v.GetPublicKey()
	if pk == nil || pk.Point == nil {
		t.Fatal("GetPublicKey returned nil")
	}
	if pk.Point.X.Cmp(commitments[0].C.X) != 0 || pk.Point.Y.Cmp(commitments[0].C.Y) != 0 {
		t.Error("GetPublicKey does not match C0")
	}
}
