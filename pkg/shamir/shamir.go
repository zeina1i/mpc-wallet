// Package shamir provides Shamir Secret Sharing functionality
// This wraps the HashiCorp Vault Shamir library with a more ergonomic API
// and additional utilities for MPC/VSS applications.
package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	vaultShamir "github.com/hashicorp/vault/shamir"
)

// ============= TYPES =============

// Share represents a single share in Shamir Secret Sharing
// Each participant receives one share
type Share struct {
	// Index is the participant's identifier (1, 2, 3, ...)
	// Index 0 is reserved for the secret itself
	Index int

	// Value is the share data (the actual share bytes)
	Value []byte
}

// Polynomial represents a polynomial f(x) = a₀ + a₁x + a₂x² + ...
// Used internally for understanding, but actual polynomial operations
// are handled by the Vault library
type Polynomial struct {
	// Coefficients [a₀, a₁, a₂, ...] where a₀ is the secret
	// Note: This is conceptual - Vault library handles this internally
	Coefficients []*big.Int
}

// Config holds configuration for Shamir Secret Sharing
type Config struct {
	// Threshold is minimum shares needed to reconstruct (t)
	Threshold int

	// Total is total number of shares to create (n)
	Total int

	// Must satisfy: 1 <= Threshold <= Total
}

// ============= ERRORS =============

var (
	ErrInvalidThreshold   = errors.New("threshold must be >= 1 and <= total")
	ErrInvalidTotal       = errors.New("total must be >= threshold")
	ErrInsufficientShares = errors.New("insufficient shares for reconstruction")
	ErrEmptySecret        = errors.New("secret cannot be empty")
	ErrDuplicateIndex     = errors.New("duplicate share indices detected")
	ErrInvalidShareIndex  = errors.New("share index must be > 0")
	ErrShareIndexZero     = errors.New("share index cannot be 0 (reserved for secret)")
	ErrNilShare           = errors.New("share cannot be nil")
	ErrInvalidShareLength = errors.New("all shares must have the same length")
)

// ============= CORE FUNCTIONS =============

// Split splits a secret into n shares with threshold t
// Any t shares can reconstruct the secret, but t-1 shares reveal nothing
//
// Parameters:
//   - secret: the secret bytes to split (any length)
//   - threshold: minimum shares needed to reconstruct
//   - total: total number of shares to create
//
// Returns:
//   - Array of shares (length = total)
//   - Error if parameters are invalid
//
// Example:
//
//	secret := []byte("my secret key")
//	shares, err := Split(secret, 3, 5) // 3-of-5 threshold
//	// Returns 5 shares, any 3 can recover the secret
func Split(secret []byte, threshold, total int) ([]*Share, error) {
	// Validate inputs
	if err := validateSplitParams(secret, threshold, total); err != nil {
		return nil, err
	}

	// Use Vault's Shamir implementation
	// This handles all the polynomial math internally
	rawShares, err := vaultShamir.Split(secret, total, threshold)
	if err != nil {
		return nil, fmt.Errorf("shamir split failed: %w", err)
	}

	// Convert to our Share type with indices
	shares := make([]*Share, total)
	for i := 0; i < total; i++ {
		shares[i] = &Share{
			Index: i + 1, // Indices start at 1 (0 is reserved for secret)
			Value: rawShares[i],
		}
	}

	return shares, nil
}

// Combine reconstructs the secret from shares using Lagrange interpolation
// Requires at least threshold shares
//
// Parameters:
//   - shares: array of shares (at least threshold shares needed)
//
// Returns:
//   - Reconstructed secret bytes
//   - Error if insufficient shares or shares are invalid
//
// Example:
//
//	// Use any 3 shares from the 5 generated
//	chosenShares := []*Share{shares[0], shares[2], shares[4]}
//	secret, err := Combine(chosenShares)
//	// Returns original secret
func Combine(shares []*Share) ([]byte, error) {
	// Validate inputs
	if err := validateShares(shares); err != nil {
		return nil, err
	}

	// Convert our Share type to raw bytes for Vault library
	rawShares := make([][]byte, len(shares))
	for i, share := range shares {
		if share == nil {
			return nil, ErrNilShare
		}
		rawShares[i] = share.Value
	}

	// Use Vault's Shamir combine
	// This performs Lagrange interpolation internally
	secret, err := vaultShamir.Combine(rawShares)
	if err != nil {
		return nil, fmt.Errorf("shamir combine failed: %w", err)
	}

	return secret, nil
}

// ============= VALIDATION FUNCTIONS =============

// ValidateShares checks if shares are valid for reconstruction
//
// Checks performed:
//   - At least one share provided
//   - All shares are non-nil
//   - All share indices are unique
//   - All share indices are positive (> 0)
//   - No share has index 0 (reserved for secret)
//   - All shares have same length
//
// Parameters:
//   - shares: array of shares to validate
//
// Returns:
//   - Error describing what's invalid, or nil if valid
func ValidateShares(shares []*Share) error {
	if len(shares) == 0 {
		return ErrInsufficientShares
	}

	// Check for duplicates and invalid indices
	seen := make(map[int]bool)
	var shareLength int

	for i, share := range shares {
		if share == nil {
			return ErrNilShare
		}

		// Check index validity
		if share.Index == 0 {
			return ErrShareIndexZero
		}
		if share.Index < 0 {
			return ErrInvalidShareIndex
		}

		// Check for duplicates
		if seen[share.Index] {
			return fmt.Errorf("%w: index %d appears multiple times", ErrDuplicateIndex, share.Index)
		}
		seen[share.Index] = true

		// Check share length consistency
		if i == 0 {
			shareLength = len(share.Value)
		} else if len(share.Value) != shareLength {
			return ErrInvalidShareLength
		}
	}

	return nil
}

// validateSplitParams validates parameters for Split operation
func validateSplitParams(secret []byte, threshold, total int) error {
	if len(secret) == 0 {
		return ErrEmptySecret
	}

	if threshold < 1 {
		return ErrInvalidThreshold
	}

	if total < threshold {
		return ErrInvalidTotal
	}

	return nil
}

// validateShares is internal validation for Combine
func validateShares(shares []*Share) error {
	if len(shares) == 0 {
		return ErrInsufficientShares
	}

	return ValidateShares(shares)
}

// ============= UTILITY FUNCTIONS =============

// ShareToBytes converts a share to raw bytes
// Useful for serialization
func ShareToBytes(share *Share) []byte {
	if share == nil {
		return nil
	}
	return share.Value
}

// SharesFromBytes converts raw byte shares to Share objects
// Useful for deserialization
//
// Parameters:
//   - rawShares: array of raw share bytes from Vault library
//
// Returns:
//   - Array of Share objects with indices assigned (1, 2, 3, ...)
func SharesFromBytes(rawShares [][]byte) []*Share {
	shares := make([]*Share, len(rawShares))
	for i, raw := range rawShares {
		shares[i] = &Share{
			Index: i + 1,
			Value: raw,
		}
	}
	return shares
}

// GenerateSecret generates a cryptographically secure random secret
// Useful for testing or generating new secrets
//
// Parameters:
//   - length: number of bytes in the secret
//
// Returns:
//   - Random secret bytes
//   - Error if random generation fails
//
// Example:
//
//	secret, err := GenerateSecret(32) // 256-bit secret
func GenerateSecret(length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("secret length must be > 0")
	}

	secret := make([]byte, length)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random secret: %w", err)
	}

	return secret, nil
}

// VerifyReconstruction verifies that shares can reconstruct the original secret
// This is a test/verification utility
//
// Parameters:
//   - original: the original secret
//   - shares: shares to test
//
// Returns:
//   - true if shares correctly reconstruct the original secret
//   - false otherwise
func VerifyReconstruction(original []byte, shares []*Share) bool {
	reconstructed, err := Combine(shares)
	if err != nil {
		return false
	}

	if len(original) != len(reconstructed) {
		return false
	}

	for i := range original {
		if original[i] != reconstructed[i] {
			return false
		}
	}

	return true
}

// ============= HELPER FUNCTIONS FOR VSS =============

// These functions help integrate Shamir with VSS (Verifiable Secret Sharing)

// SecretToPolynomial converts a secret to a conceptual polynomial representation
// Note: This is for understanding - actual polynomial is inside Vault library
//
// In Shamir's scheme:
//   - Secret becomes a₀ (constant term)
//   - Random coefficients a₁, a₂, ... are generated
//   - Polynomial: f(x) = a₀ + a₁x + a₂x² + ...
//   - Shares are: f(1), f(2), f(3), ...
//
// This function helps you understand what's happening conceptually
func SecretToPolynomial(secret []byte, threshold int) *Polynomial {
	// Convert secret to big.Int (conceptual - Vault handles this differently)
	secretInt := new(big.Int).SetBytes(secret)

	// Create polynomial with secret as constant term
	// Note: Other coefficients are random (generated by Vault internally)
	coefficients := make([]*big.Int, threshold)
	coefficients[0] = secretInt

	// Remaining coefficients are conceptually random
	// (In practice, Vault library generates these)
	for i := 1; i < threshold; i++ {
		coefficients[i] = big.NewInt(0) // Placeholder
	}

	return &Polynomial{
		Coefficients: coefficients,
	}
}

// GetShareIndex returns the index of a share
// Useful for tracking which participant has which share
func GetShareIndex(share *Share) int {
	if share == nil {
		return 0
	}
	return share.Index
}

// GetShareValue returns the value bytes of a share
// Useful for serialization or transmission
func GetShareValue(share *Share) []byte {
	if share == nil {
		return nil
	}
	return share.Value
}

// CreateShare creates a share from index and value
// Useful when reconstructing Share objects from stored data
func CreateShare(index int, value []byte) *Share {
	return &Share{
		Index: index,
		Value: value,
	}
}

// ============= ADVANCED UTILITIES =============

// SelectShares randomly selects n shares from the pool
// Useful for testing different combinations
//
// Parameters:
//   - shares: pool of available shares
//   - count: number of shares to select
//
// Returns:
//   - Randomly selected shares
//   - Error if count > available shares
func SelectShares(shares []*Share, count int) ([]*Share, error) {
	if count > len(shares) {
		return nil, fmt.Errorf("cannot select %d shares from pool of %d", count, len(shares))
	}

	if count == len(shares) {
		return shares, nil
	}

	// Create indices and shuffle
	indices := make([]int, len(shares))
	for i := range indices {
		indices[i] = i
	}

	// Fisher-Yates shuffle
	for i := len(indices) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		jInt := int(j.Int64())
		indices[i], indices[jInt] = indices[jInt], indices[i]
	}

	// Select first 'count' shuffled indices
	selected := make([]*Share, count)
	for i := 0; i < count; i++ {
		selected[i] = shares[indices[i]]
	}

	return selected, nil
}

// TestAllCombinations tests all possible combinations of threshold shares
// Useful for verification that all combinations work correctly
//
// Parameters:
//   - shares: all available shares
//   - threshold: minimum shares needed
//   - expectedSecret: the original secret to verify against
//
// Returns:
//   - true if ALL combinations successfully reconstruct the secret
//   - false if any combination fails
//
// Example:
//
//	// For 3-of-5, tests all C(5,3) = 10 combinations
//	allWork := TestAllCombinations(shares, 3, originalSecret)
func TestAllCombinations(shares []*Share, threshold int, expectedSecret []byte) bool {
	if len(shares) < threshold {
		return false
	}

	// Generate all combinations
	combinations := generateCombinations(len(shares), threshold)

	for _, combo := range combinations {
		// Select shares for this combination
		selectedShares := make([]*Share, threshold)
		for i, idx := range combo {
			selectedShares[i] = shares[idx]
		}

		// Try to reconstruct
		if !VerifyReconstruction(expectedSecret, selectedShares) {
			return false
		}
	}

	return true
}

// generateCombinations generates all C(n, k) combinations
// Helper for TestAllCombinations
func generateCombinations(n, k int) [][]int {
	var result [][]int
	combination := make([]int, k)

	var generate func(start, index int)
	generate = func(start, index int) {
		if index == k {
			combo := make([]int, k)
			copy(combo, combination)
			result = append(result, combo)
			return
		}

		for i := start; i < n; i++ {
			combination[index] = i
			generate(i+1, index+1)
		}
	}

	generate(0, 0)
	return result
}

// ============= INFORMATION FUNCTIONS =============

// GetThresholdFromShares attempts to determine the threshold from shares
// Note: This is estimated - the actual threshold is not stored in shares
// Returns minimum reasonable threshold based on share count
func GetThresholdFromShares(shares []*Share) int {
	// Vault library doesn't encode threshold in shares
	// This is a reasonable guess: at least half
	return (len(shares) + 1) / 2
}

// PrintShareInfo prints information about a share (for debugging)
// Useful during development and testing
func PrintShareInfo(share *Share) string {
	if share == nil {
		return "Share: nil"
	}

	return fmt.Sprintf("Share{Index: %d, Length: %d bytes, Value: %x...}",
		share.Index,
		len(share.Value),
		share.Value[:min(4, len(share.Value))],
	)
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============= CONSTANTS =============

const (
	// RecommendedSecretSize is the recommended minimum secret size in bytes
	// 32 bytes = 256 bits is standard for cryptographic keys
	RecommendedSecretSize = 32

	// MaxRecommendedTotal is the maximum recommended number of shares
	// Too many shares increases risk of compromise
	MaxRecommendedTotal = 255

	// MinRecommendedThreshold is the minimum recommended threshold
	// Threshold of 1 defeats the purpose of secret sharing
	MinRecommendedThreshold = 2
)
