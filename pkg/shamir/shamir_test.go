package shamir

import (
	"errors"
	"math/big"
	"testing"
)

// secp256k1 order used throughout tests
var N = Secp256k1Order()

func TestBasicSplitAndCombine(t *testing.T) {
	secret := big.NewInt(12345)
	threshold := 3
	total := 5

	shares, err := Split(secret, N, threshold, total)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if len(shares) != total {
		t.Fatalf("expected %d shares, got %d", total, len(shares))
	}

	reconstructed, err := Combine(shares[0:threshold], N)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if reconstructed.Cmp(secret) != 0 {
		t.Fatalf("reconstructed %v, want %v", reconstructed, secret)
	}
}

func TestInsufficientSharesGiveWrongResult(t *testing.T) {
	secret := big.NewInt(99999)
	shares, _ := Split(secret, N, 3, 5)

	// With only 2 shares (need 3), Lagrange gives a wrong value (not an error)
	reconstructed, err := Combine(shares[0:2], N)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reconstructed.Cmp(secret) == 0 {
		t.Fatal("should not reconstruct secret with fewer than threshold shares")
	}
}

func TestAllCombinationsWork(t *testing.T) {
	secret := big.NewInt(42)
	threshold := 3
	total := 5

	shares, _ := Split(secret, N, threshold, total)

	// Test all C(5,3) = 10 combinations
	for i := 0; i < total; i++ {
		for j := i + 1; j < total; j++ {
			for k := j + 1; k < total; k++ {
				combo := []*Share{shares[i], shares[j], shares[k]}
				reconstructed, err := Combine(combo, N)
				if err != nil {
					t.Fatalf("Combine failed for combo (%d,%d,%d): %v", i, j, k, err)
				}
				if reconstructed.Cmp(secret) != 0 {
					t.Fatalf("combo (%d,%d,%d): got %v, want %v", i, j, k, reconstructed, secret)
				}
			}
		}
	}
}

func TestMoreThanThresholdShares(t *testing.T) {
	secret := big.NewInt(7777)
	shares, _ := Split(secret, N, 3, 5)

	// Use 4 shares (more than threshold of 3)
	reconstructed, err := Combine(shares[0:4], N)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}
	if reconstructed.Cmp(secret) != 0 {
		t.Fatalf("got %v, want %v", reconstructed, secret)
	}
}

func TestValidation(t *testing.T) {
	// Nil share
	err := validateShares([]*Share{nil})
	if !errors.Is(err, ErrNilShare) {
		t.Errorf("expected ErrNilShare, got %v", err)
	}

	// Index zero
	err = validateShares([]*Share{{Index: 0, Value: big.NewInt(1)}})
	if !errors.Is(err, ErrInvalidShareIndex) {
		t.Errorf("expected ErrInvalidShareIndex, got %v", err)
	}

	// Duplicate index
	s := &Share{Index: 1, Value: big.NewInt(1)}
	err = validateShares([]*Share{s, s})
	if !errors.Is(err, ErrDuplicateIndex) {
		t.Errorf("expected ErrDuplicateIndex, got %v", err)
	}
}

func TestPolynomialEvaluateAt(t *testing.T) {
	// f(x) = 5 + 3x + 2x²  mod N
	// f(1) = 5+3+2 = 10
	// f(2) = 5+6+8 = 19
	coeffs := []*big.Int{big.NewInt(5), big.NewInt(3), big.NewInt(2)}
	poly := &Polynomial{coefficients: coeffs, modulus: N}

	if got := poly.EvaluateAt(big.NewInt(1)); got.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("f(1) = %v, want 10", got)
	}
	if got := poly.EvaluateAt(big.NewInt(2)); got.Cmp(big.NewInt(19)) != 0 {
		t.Fatalf("f(2) = %v, want 19", got)
	}
}

func TestPolynomialGetSecret(t *testing.T) {
	secret := big.NewInt(1337)
	poly, err := NewPolynomial(secret, N, 3)
	if err != nil {
		t.Fatalf("NewPolynomial failed: %v", err)
	}
	if poly.GetSecret().Cmp(secret) != 0 {
		t.Fatalf("GetSecret() = %v, want %v", poly.GetSecret(), secret)
	}
	if poly.GetDegree() != 2 {
		t.Fatalf("degree = %d, want 2", poly.GetDegree())
	}
}

func TestLargeSecret(t *testing.T) {
	// Secret close to N-1 (max valid scalar for secp256k1)
	secret := new(big.Int).Sub(N, big.NewInt(1))

	shares, err := Split(secret, N, 3, 5)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	reconstructed, err := Combine(shares[0:3], N)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}
	if reconstructed.Cmp(secret) != 0 {
		t.Fatalf("got %v, want %v", reconstructed, secret)
	}
}
