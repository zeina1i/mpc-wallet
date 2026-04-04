package vss

import (
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/zeina1i/mpc-wallet/pkg/shamir"
)

// toShamirShares converts []*vss.Share → []*shamir.Share for reconstruction.
// The types are structurally identical but live in different packages.
func toShamirShares(shares []*Share) []*shamir.Share {
	out := make([]*shamir.Share, len(shares))
	for i, s := range shares {
		out[i] = &shamir.Share{Index: s.Index, Value: s.Value}
	}
	return out
}

// newTestParams builds Params using P-256 (matches the pedersen package internally).
// G = curve generator, H = hash-derived second point, N = curve order.
func newTestParams() *Params {

	curve := elliptic.P256()

	G := &Point{X: curve.Params().Gx, Y: curve.Params().Gy}

	// Derive H the same way pedersen does — H = h·G where h = SHA256("pedersen-H" || seed)
	h := sha256.New()
	h.Write([]byte("pedersen-H"))
	h.Write([]byte("test-seed"))
	hScalar := new(big.Int).SetBytes(h.Sum(nil))
	hScalar.Mod(hScalar, curve.Params().N)
	hX, hY := curve.ScalarBaseMult(hScalar.Bytes())

	return &Params{
		G:     G,
		H:     &Point{X: hX, Y: hY},
		Curve: curve,
		N:     curve.Params().N,
	}
}

func TestNewDealer_ReturnsCounts(t *testing.T) {
	params := newTestParams()
	secret := big.NewInt(12345)
	threshold, total := 3, 5

	d, err := NewDealer(params, secret, threshold, total)
	if err != nil {
		t.Fatalf("NewDealer failed: %v", err)
	}

	if d.GetThreshold() != threshold {
		t.Errorf("threshold = %d, want %d", d.GetThreshold(), threshold)
	}
	if d.GetTotal() != total {
		t.Errorf("total = %d, want %d", d.GetTotal(), total)
	}
}

func TestNewDealer_CommitmentsLength(t *testing.T) {
	params := newTestParams()
	d, _ := NewDealer(params, big.NewInt(999), 3, 5)

	// One commitment per polynomial coefficient → exactly threshold commitments
	if len(d.GetCommitments()) != 3 {
		t.Errorf("len(commitments) = %d, want 3", len(d.GetCommitments()))
	}
}

func TestNewDealer_CommitmentsAreValidPoints(t *testing.T) {
	params := newTestParams()
	d, _ := NewDealer(params, big.NewInt(999), 3, 5)

	for i, c := range d.GetCommitments() {
		if c == nil || c.C == nil {
			t.Errorf("commitment[%d] is nil", i)
			continue
		}
		if !params.Curve.IsOnCurve(c.C.X, c.C.Y) {
			t.Errorf("commitment[%d] is not on the curve", i)
		}
	}
}

func TestNewDealer_SharesLength(t *testing.T) {
	params := newTestParams()
	d, _ := NewDealer(params, big.NewInt(42), 3, 5)

	if len(d.GetShares()) != 5 {
		t.Errorf("len(shares) = %d, want 5", len(d.GetShares()))
	}
}

func TestNewDealer_ShareIndices(t *testing.T) {
	params := newTestParams()
	d, _ := NewDealer(params, big.NewInt(42), 3, 5)

	// Shares must be indexed 1..total (not 0-based)
	for i, s := range d.GetShares() {
		if s.Index != i+1 {
			t.Errorf("shares[%d].Index = %d, want %d", i, s.Index, i+1)
		}
	}
}

func TestNewDealer_GetShareForParticipant(t *testing.T) {
	params := newTestParams()
	d, _ := NewDealer(params, big.NewInt(42), 3, 5)

	for i := 1; i <= 5; i++ {
		s, err := d.GetShareForParticipant(i)
		if err != nil {
			t.Errorf("GetShareForParticipant(%d) error: %v", i, err)
			continue
		}
		if s.Index != i {
			t.Errorf("GetShareForParticipant(%d).Index = %d", i, s.Index)
		}
	}
}

func TestNewDealer_GetShareForParticipant_InvalidIndex(t *testing.T) {
	params := newTestParams()
	d, _ := NewDealer(params, big.NewInt(42), 3, 5)

	if _, err := d.GetShareForParticipant(0); err == nil {
		t.Error("expected error for index 0")
	}
	if _, err := d.GetShareForParticipant(6); err == nil {
		t.Error("expected error for index > total")
	}
}

func TestNewDealer_PublicKey(t *testing.T) {
	params := newTestParams()
	secret := big.NewInt(12345)
	d, _ := NewDealer(params, secret, 3, 5)

	pk := d.GetPublicKey()
	if pk == nil || pk.Point == nil {
		t.Fatal("public key is nil")
	}
	if !params.Curve.IsOnCurve(pk.Point.X, pk.Point.Y) {
		t.Error("public key is not on curve")
	}

	// PK must equal secret·G
	expectedX, expectedY := params.Curve.ScalarBaseMult(secret.Bytes())
	if pk.Point.X.Cmp(expectedX) != 0 || pk.Point.Y.Cmp(expectedY) != 0 {
		t.Error("public key does not equal secret·G")
	}
}

func TestNewDealer_SecretReconstruction(t *testing.T) {
	params := newTestParams()
	secret := big.NewInt(99999)
	threshold, total := 3, 5

	d, _ := NewDealer(params, secret, threshold, total)
	shares := d.GetShares()

	// Any threshold shares must reconstruct the secret
	reconstructed, err := shamir.Combine(toShamirShares(shares[0:threshold]), params.N)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}
	if reconstructed.Cmp(secret) != 0 {
		t.Errorf("reconstructed = %v, want %v", reconstructed, secret)
	}
}

func TestNewDealer_InsufficientSharesWrongResult(t *testing.T) {
	params := newTestParams()
	secret := big.NewInt(99999)

	d, _ := NewDealer(params, secret, 3, 5)
	shares := d.GetShares()

	// t-1 shares must NOT reconstruct the secret
	reconstructed, _ := shamir.Combine(toShamirShares(shares[0:2]), params.N)
	if reconstructed.Cmp(secret) == 0 {
		t.Error("t-1 shares should not reconstruct the secret")
	}
}

func TestNewDealer_AllCombinationsReconstruct(t *testing.T) {
	params := newTestParams()
	secret := big.NewInt(7777)
	threshold, total := 3, 5

	d, _ := NewDealer(params, secret, threshold, total)
	shares := d.GetShares()

	// All C(5,3)=10 combinations must reconstruct correctly
	for i := 0; i < total; i++ {
		for j := i + 1; j < total; j++ {
			for k := j + 1; k < total; k++ {
				combo := []*Share{shares[i], shares[j], shares[k]}
				reconstructed, err := shamir.Combine(toShamirShares(combo), params.N)
				if err != nil {
					t.Errorf("combo (%d,%d,%d) Combine error: %v", i, j, k, err)
					continue
				}
				if reconstructed.Cmp(secret) != 0 {
					t.Errorf("combo (%d,%d,%d): got %v, want %v", i, j, k, reconstructed, secret)
				}
			}
		}
	}
}
