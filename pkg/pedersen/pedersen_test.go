package pedersen

import (
	"crypto/rand"
	"math/big"
	"testing"
)

var impl = Impl{}

func setupParams(t *testing.T) *Params {
	t.Helper()
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		t.Fatalf("failed to generate seed: %v", err)
	}
	params, err := impl.Setup(seed)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	return params
}

func randomBlinding(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		t.Fatalf("failed to generate blinding: %v", err)
	}
	return b
}

func TestSetup_ReturnsValidParams(t *testing.T) {
	params := setupParams(t)

	if params.G == nil || params.G.X == nil || params.G.Y == nil {
		t.Fatal("G point is nil or incomplete")
	}
	if params.H == nil || params.H.X == nil || params.H.Y == nil {
		t.Fatal("H point is nil or incomplete")
	}
}

func TestSetup_DifferentSeedsProduceDifferentH(t *testing.T) {
	params1, _ := impl.Setup([]byte("seed-one"))
	params2, _ := impl.Setup([]byte("seed-two"))

	if params1.H.X.Cmp(params2.H.X) == 0 && params1.H.Y.Cmp(params2.H.Y) == 0 {
		t.Fatal("different seeds should produce different H points")
	}
}

func TestSetup_SameSeedProducesSameH(t *testing.T) {
	seed := []byte("deterministic-seed")
	params1, _ := impl.Setup(seed)
	params2, _ := impl.Setup(seed)

	if params1.H.X.Cmp(params2.H.X) != 0 || params1.H.Y.Cmp(params2.H.Y) != 0 {
		t.Fatal("same seed should produce the same H point")
	}
}

func TestCommitAndVerify(t *testing.T) {
	params := setupParams(t)
	value := big.NewInt(42)
	blinding := randomBlinding(t)

	commitment, opening, err := impl.Commit(params, value, blinding)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Copy value/blinding before Verify mutates them
	verifyOpening := &Opening{
		Value:    new(big.Int).Set(opening.Value),
		Blinding: new(big.Int).Set(opening.Blinding),
	}

	if !impl.Verify(params, commitment, verifyOpening) {
		t.Fatal("Verify returned false for a valid commitment")
	}
}

func TestVerify_WrongValueFails(t *testing.T) {
	params := setupParams(t)
	blinding := randomBlinding(t)

	commitment, _, err := impl.Commit(params, big.NewInt(42), blinding)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	wrongOpening := &Opening{
		Value:    big.NewInt(99),
		Blinding: new(big.Int).SetBytes(blinding),
	}

	if impl.Verify(params, commitment, wrongOpening) {
		t.Fatal("Verify should return false for wrong value")
	}
}

func TestVerify_WrongBlindingFails(t *testing.T) {
	params := setupParams(t)
	value := big.NewInt(42)
	blinding := randomBlinding(t)

	commitment, opening, err := impl.Commit(params, value, blinding)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	wrongOpening := &Opening{
		Value:    new(big.Int).Set(opening.Value),
		Blinding: big.NewInt(9999),
	}

	if impl.Verify(params, commitment, wrongOpening) {
		t.Fatal("Verify should return false for wrong blinding")
	}
}

func TestVerify_WrongParamsFails(t *testing.T) {
	params1 := setupParams(t)
	params2 := setupParams(t)
	value := big.NewInt(42)
	blinding := randomBlinding(t)

	commitment, opening, err := impl.Commit(params1, value, blinding)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	verifyOpening := &Opening{
		Value:    new(big.Int).Set(opening.Value),
		Blinding: new(big.Int).Set(opening.Blinding),
	}

	if impl.Verify(params2, commitment, verifyOpening) {
		t.Fatal("Verify should return false when using different params")
	}
}

func TestCommit_ZeroValue(t *testing.T) {
	params := setupParams(t)
	blinding := randomBlinding(t)

	commitment, opening, err := impl.Commit(params, big.NewInt(0), blinding)
	if err != nil {
		t.Fatalf("Commit failed for zero value: %v", err)
	}

	verifyOpening := &Opening{
		Value:    new(big.Int).Set(opening.Value),
		Blinding: new(big.Int).Set(opening.Blinding),
	}

	if !impl.Verify(params, commitment, verifyOpening) {
		t.Fatal("Verify failed for zero value commitment")
	}
}

func TestCommit_LargeValue(t *testing.T) {
	params := setupParams(t)
	blinding := randomBlinding(t)

	large := new(big.Int).Lsh(big.NewInt(1), 200)

	commitment, opening, err := impl.Commit(params, large, blinding)
	if err != nil {
		t.Fatalf("Commit failed for large value: %v", err)
	}

	verifyOpening := &Opening{
		Value:    new(big.Int).Set(opening.Value),
		Blinding: new(big.Int).Set(opening.Blinding),
	}

	if !impl.Verify(params, commitment, verifyOpening) {
		t.Fatal("Verify failed for large value commitment")
	}
}

func TestCommit_IsDeterministic(t *testing.T) {
	params := setupParams(t)
	value := big.NewInt(42)
	blinding := []byte("fixed-blinding-value-0000000000")

	c1, _, _ := impl.Commit(params, new(big.Int).Set(value), blinding)
	c2, _, _ := impl.Commit(params, new(big.Int).Set(value), blinding)

	if c1.Point.X.Cmp(c2.Point.X) != 0 || c1.Point.Y.Cmp(c2.Point.Y) != 0 {
		t.Fatal("Commit should be deterministic for the same inputs")
	}
}

func TestCommit_DifferentValuesProduceDifferentCommitments(t *testing.T) {
	params := setupParams(t)
	blinding := randomBlinding(t)

	c1, _, _ := impl.Commit(params, big.NewInt(1), blinding)
	c2, _, _ := impl.Commit(params, big.NewInt(2), blinding)

	if c1.Point.X.Cmp(c2.Point.X) == 0 && c1.Point.Y.Cmp(c2.Point.Y) == 0 {
		t.Fatal("different values should produce different commitments")
	}
}
