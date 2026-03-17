package shamir

import (
	"bytes"
	"errors"
	"testing"
)

func TestBasicSplitAndCombine(t *testing.T) {
	secret := []byte("my secret key")
	threshold := 3
	total := 5

	// Split
	shares, err := Split(secret, threshold, total)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if len(shares) != total {
		t.Fatalf("Expected %d shares, got %d", total, len(shares))
	}

	// Combine with threshold shares
	selectedShares := shares[0:threshold]
	reconstructed, err := Combine(selectedShares)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, reconstructed) {
		t.Fatalf("Reconstructed secret doesn't match.\nExpected: %x\nGot: %x", secret, reconstructed)
	}
}

func TestInsufficientShares(t *testing.T) {
	secret := []byte("my secret key")
	threshold := 3
	total := 5

	shares, _ := Split(secret, threshold, total)

	// Try with only 2 shares (need 3)
	insufficientShares := shares[0:2]
	_, err := Combine(insufficientShares)

	// Vault library may or may not error, but reconstruction will be wrong
	if err == nil {
		// If no error, the result should be incorrect
		reconstructed, _ := Combine(insufficientShares)
		if bytes.Equal(secret, reconstructed) {
			t.Fatal("Should not reconstruct with insufficient shares")
		}
	}
}

func TestAllCombinationsWork(t *testing.T) {
	secret := []byte("test secret")
	threshold := 3
	total := 5

	shares, _ := Split(secret, threshold, total)

	// Test all C(5,3) = 10 combinations
	allWork := TestAllCombinations(shares, threshold, secret)
	if !allWork {
		t.Fatal("Not all combinations work")
	}
}

func TestValidation(t *testing.T) {
	secret := []byte("test")
	shares, _ := Split(secret, 3, 5)

	// Valid shares
	err := ValidateShares(shares)
	if err != nil {
		t.Errorf("Valid shares rejected: %v", err)
	}

	// Nil share
	invalidShares := []*Share{nil}
	err = ValidateShares(invalidShares)
	if !errors.Is(err, ErrNilShare) {
		t.Errorf("Expected ErrNilShare, got %v", err)
	}

	// Duplicate index
	duplicateShares := []*Share{shares[0], shares[0]}
	err = ValidateShares(duplicateShares)
	if !errors.Is(err, ErrDuplicateIndex) {
		t.Errorf("Expected ErrDuplicateIndex, got %v", err)
	}

	// Index zero
	zeroShare := &Share{Index: 0, Value: []byte("test")}
	err = ValidateShares([]*Share{zeroShare})
	if !errors.Is(err, ErrShareIndexZero) {
		t.Errorf("Expected ErrShareIndexZero, got %v", err)
	}
}

func TestMoreThanThresholdShares(t *testing.T) {
	secret := []byte("test secret")
	threshold := 3
	total := 5

	shares, _ := Split(secret, threshold, total)

	// Use 4 shares (more than threshold of 3)
	selectedShares := shares[0:4]
	reconstructed, err := Combine(selectedShares)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, reconstructed) {
		t.Fatal("Reconstruction with extra shares failed")
	}
}

func TestGenerateSecret(t *testing.T) {
	secret, err := GenerateSecret(32)
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	if len(secret) != 32 {
		t.Fatalf("Expected 32 bytes, got %d", len(secret))
	}

	// Should be able to split and combine
	shares, _ := Split(secret, 3, 5)
	reconstructed, _ := Combine(shares[0:3])

	if !bytes.Equal(secret, reconstructed) {
		t.Fatal("Generated secret failed reconstruction")
	}
}

func TestSelectShares(t *testing.T) {
	secret := []byte("test")
	shares, _ := Split(secret, 3, 5)

	selected, err := SelectShares(shares, 3)
	if err != nil {
		t.Fatalf("SelectShares failed: %v", err)
	}

	if len(selected) != 3 {
		t.Fatalf("Expected 3 shares, got %d", len(selected))
	}

	// Should be able to reconstruct
	reconstructed, _ := Combine(selected)
	if !bytes.Equal(secret, reconstructed) {
		t.Fatal("Selected shares failed reconstruction")
	}
}

func TestZeroSecret(t *testing.T) {
	// Secret of all zeros should work
	secret := make([]byte, 32)
	shares, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split of zero secret failed: %v", err)
	}

	reconstructed, err := Combine(shares[0:3])
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, reconstructed) {
		t.Fatal("Zero secret reconstruction failed")
	}
}

func TestLargeSecret(t *testing.T) {
	// Test with large secret (1KB)
	secret := make([]byte, 1024)
	for i := range secret {
		secret[i] = byte(i % 256)
	}

	shares, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split of large secret failed: %v", err)
	}

	reconstructed, err := Combine(shares[0:3])
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, reconstructed) {
		t.Fatal("Large secret reconstruction failed")
	}
}

func TestShareSerialization(t *testing.T) {
	secret := []byte("test")
	shares, _ := Split(secret, 3, 5)

	// Convert to bytes and back
	rawShares := make([][]byte, len(shares))
	for i, share := range shares {
		rawShares[i] = ShareToBytes(share)
	}

	reconstructedShares := SharesFromBytes(rawShares)

	// Should still work
	secret2, err := Combine(reconstructedShares[0:3])
	if err != nil {
		t.Fatalf("Combine after serialization failed: %v", err)
	}

	if !bytes.Equal(secret, secret2) {
		t.Fatal("Serialization round-trip failed")
	}
}
