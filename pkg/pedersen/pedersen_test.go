package pedersen

import (
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

var testSeed = []byte("pedersen-test-seed")

func setupParams(t *testing.T) *Params {
	t.Helper()
	params, err := Setup(testSeed)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	return params
}

// TestSetupHOnCurve verifies that H produced by Setup is a valid curve point.
func TestSetupHOnCurve(t *testing.T) {
	params := setupParams(t)
	curve := btcec.S256()
	if !curve.IsOnCurve(params.H.X, params.H.Y) {
		t.Fatal("H is not on the curve")
	}
}

// TestSetupGMatchesCurveGenerator verifies that G matches secp256k1's base point.
func TestSetupGMatchesCurveGenerator(t *testing.T) {
	params := setupParams(t)
	curve := btcec.S256()
	if params.G.X.Cmp(curve.Params().Gx) != 0 || params.G.Y.Cmp(curve.Params().Gy) != 0 {
		t.Fatal("G does not match the curve base point")
	}
}

// TestSetupDeterministic verifies that the same seed produces the same params.
func TestSetupDeterministic(t *testing.T) {
	p1, _ := Setup(testSeed)
	p2, _ := Setup(testSeed)
	if p1.H.X.Cmp(p2.H.X) != 0 || p1.H.Y.Cmp(p2.H.Y) != 0 {
		t.Fatal("Setup is not deterministic for the same seed")
	}
}

// TestSetupDifferentSeedsDifferentH verifies that different seeds produce different H.
func TestSetupDifferentSeedsDifferentH(t *testing.T) {
	p1, _ := Setup([]byte("seed-a"))
	p2, _ := Setup([]byte("seed-b"))
	if p1.H.X.Cmp(p2.H.X) == 0 && p1.H.Y.Cmp(p2.H.Y) == 0 {
		t.Fatal("different seeds produced the same H")
	}
}

// TestCommitVerifyRoundtrip is the happy path: commit then verify succeeds.
func TestCommitVerifyRoundtrip(t *testing.T) {
	params := setupParams(t)
	value := big.NewInt(42)
	blinding := big.NewInt(12345)

	commitment, opening, err := Commit(params, value, blinding)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	if !Verify(params, commitment, opening) {
		t.Fatal("Verify returned false for a valid commitment")
	}
}

// TestCommitWrongValueFails verifies that tampering with the value breaks verification.
func TestCommitWrongValueFails(t *testing.T) {
	params := setupParams(t)
	commitment, opening, _ := Commit(params, big.NewInt(42), big.NewInt(99))
	opening.Value = big.NewInt(43) // tamper
	if Verify(params, commitment, opening) {
		t.Fatal("Verify should fail with a wrong value")
	}
}

// TestCommitWrongBlindingFails verifies that tampering with the blinding factor breaks verification.
func TestCommitWrongBlindingFails(t *testing.T) {
	params := setupParams(t)
	commitment, opening, _ := Commit(params, big.NewInt(42), big.NewInt(99))
	opening.Blinding = big.NewInt(100) // tamper
	if Verify(params, commitment, opening) {
		t.Fatal("Verify should fail with a wrong blinding factor")
	}
}

// TestCommitHidingDifferentBlindings verifies that committing the same value with
// different blinding factors produces different commitments (hiding property).
func TestCommitHidingDifferentBlindings(t *testing.T) {
	params := setupParams(t)
	c1, _, _ := Commit(params, big.NewInt(42), big.NewInt(1))
	c2, _, _ := Commit(params, big.NewInt(42), big.NewInt(2))
	if c1.Point.X.Cmp(c2.Point.X) == 0 && c1.Point.Y.Cmp(c2.Point.Y) == 0 {
		t.Fatal("same value with different blindings produced the same commitment")
	}
}

// TestCommitHomomorphic verifies the additive homomorphic property:
// Commit(v1,r1) + Commit(v2,r2) == Commit(v1+v2, r1+r2)
func TestCommitHomomorphic(t *testing.T) {
	params := setupParams(t)
	v1, r1 := big.NewInt(10), big.NewInt(100)
	v2, r2 := big.NewInt(20), big.NewInt(200)

	c1, _, _ := Commit(params, v1, r1)
	c2, _, _ := Commit(params, v2, r2)

	curve := btcec.S256()
	sumX, sumY := curve.Add(c1.Point.X, c1.Point.Y, c2.Point.X, c2.Point.Y)

	n := curve.Params().N
	vSum := new(big.Int).Mod(new(big.Int).Add(v1, v2), n)
	rSum := new(big.Int).Mod(new(big.Int).Add(r1, r2), n)
	cSum, _, err := Commit(params, vSum, rSum)
	if err != nil {
		t.Fatalf("Commit(v1+v2, r1+r2) failed: %v", err)
	}

	if sumX.Cmp(cSum.Point.X) != 0 || sumY.Cmp(cSum.Point.Y) != 0 {
		t.Fatal("homomorphic addition property does not hold")
	}
}

// TestCommitZeroValueError verifies that a zero value is rejected.
func TestCommitZeroValueError(t *testing.T) {
	params := setupParams(t)
	_, _, err := Commit(params, big.NewInt(0), big.NewInt(99))
	if err == nil {
		t.Fatal("expected error for zero value")
	}
}

// TestCommitZeroBlindingError verifies that a zero blinding factor is rejected.
func TestCommitZeroBlindingError(t *testing.T) {
	params := setupParams(t)
	_, _, err := Commit(params, big.NewInt(42), big.NewInt(0))
	if err == nil {
		t.Fatal("expected error for zero blinding factor")
	}
}

// TestCommitLargeValue verifies that a value larger than N is handled correctly via mod reduction.
func TestCommitLargeValue(t *testing.T) {
	params := setupParams(t)
	curve := btcec.S256()
	n := curve.Params().N

	// value = N + 42, which should behave identically to 42
	large := new(big.Int).Add(n, big.NewInt(42))
	blinding := big.NewInt(7)

	cLarge, oLarge, err := Commit(params, large, blinding)
	if err != nil {
		t.Fatalf("Commit with large value failed: %v", err)
	}
	cSmall, _, err := Commit(params, big.NewInt(42), blinding)
	if err != nil {
		t.Fatalf("Commit with small value failed: %v", err)
	}

	if cLarge.Point.X.Cmp(cSmall.Point.X) != 0 || cLarge.Point.Y.Cmp(cSmall.Point.Y) != 0 {
		t.Fatal("value >= N was not correctly reduced mod N")
	}
	if !Verify(params, cLarge, oLarge) {
		t.Fatal("Verify failed for large value commitment")
	}
}
