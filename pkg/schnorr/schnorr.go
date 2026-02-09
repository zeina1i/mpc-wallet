package schnorr

import (
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
)

// Point represents a point on an elliptic curve
type Point struct {
	X, Y *big.Int
}

// Signature represents a Schnorr signature (R, s)
type Signature struct {
	R *Point   // commitment point
	S *big.Int // response scalar
}

// KeyPair holds a private/public key pair
type KeyPair struct {
	PrivateKey *big.Int
	PublicKey  *Point
}

type Schnorr interface {
	// GenerateKeyPair creates a new random key pair
	GenerateKeyPair(entropy []byte) (*KeyPair, error)
	Sign(keyPair *KeyPair, message []byte) (*Signature, error)

	// Verify checks if a signature is valid
	// Steps you'll implement:
	//   1. e = H(R || P || m)
	//   2. Check: s*G == R + e*P
	Verify(publicKey *Point, message []byte, sig *Signature) bool
}

type Impl struct{}

func (Impl) GenerateKeyPair(xEntropy []byte) (*KeyPair, error) {
	curve := elliptic.P256()

	x := new(big.Int).SetBytes(xEntropy)
	x.Mod(x, curve.Params().N)

	px, py := curve.ScalarBaseMult(x.Bytes())

	return &KeyPair{
		PrivateKey: x,
		PublicKey:  &Point{X: px, Y: py},
	}, nil
}

func (Impl) Sign(keyPair *KeyPair, message []byte, kEntropy []byte) (*Signature, error) {
	curve := elliptic.P256() // Uncomment when implementing

	// Step 1: Pick random nonce k (provided via kEntropy)
	// - k must be in range [1, n-1] where n is the curve order
	// - k = kEntropy mod n
	k := new(big.Int).SetBytes(kEntropy)
	k.Mod(k, curve.Params().N)

	// Step 2: Compute commitment R = k*G
	// - G is the generator point of the curve
	// - R is the "commitment" that will be part of the signature
	rX, rY := curve.ScalarBaseMult(k.Bytes())
	R := &Point{X: rX, Y: rY}

	// Step 3: Compute challenge e = H(R || P || m)
	// - Hash the commitment R, public key P, and message m together
	// - This binds the signature to all three values
	e := computeE(R, keyPair.PublicKey, message)

	// Step 4: Compute response s = k + e*x (mod n)
	// - x is the private key
	// - s proves knowledge of x without revealing it
	s := new(big.Int).Mul(e, keyPair.PrivateKey)
	s.Add(s, k).Mod(s, curve.Params().N)

	// Step 5: Return signature (R, s)
	return &Signature{R: R, S: s}, nil
}

func (Impl) Verify(publicKey *Point, message []byte, sig *Signature) bool {
	curve := elliptic.P256()
	// Step 1: Compute challenge e = H(R || P || m)
	e := computeE(sig.R, publicKey, message)
	// - Use the same hash function as in Sign
	// - R comes from the signature, P is the public key
	//e := computeE(sig.R, publicKey, message)

	// Step 2: Compute left side of verification equation: sG = s*G
	// - Scalar multiply s by generator point G
	leftX, leftY := curve.ScalarBaseMult(sig.S.Bytes())
	left := &Point{X: leftX, Y: leftY}

	// Step 3: Compute right side of verification equation: R + eP
	// - First compute e*P (scalar multiply e by public key)
	// - Then add R + e*P (point addition)
	eMultPX, eMultpY := curve.ScalarMult(publicKey.X, publicKey.Y, e.Bytes())
	rightX, rightY := curve.Add(sig.R.X, sig.R.Y, eMultPX, eMultpY)
	right := &Point{X: rightX, Y: rightY}

	// Step 4: Compare: sG == R + eP
	// - If the x and y coordinates match, signature is valid
	// - Return true if valid, false otherwise

	// TODO: Implement the steps above
	return left.X.Cmp(right.X) == 0 && left.Y.Cmp(right.Y) == 0
}

// Serialize R, P, and message into bytes, then hash
func computeE(R, P *Point, message []byte) *big.Int {
	curve := elliptic.P256()
	h := sha256.New()

	// R (commitment point)
	h.Write(R.X.Bytes())
	h.Write(R.Y.Bytes())

	// P (public key)
	h.Write(P.X.Bytes())
	h.Write(P.Y.Bytes())

	// m (message)
	h.Write(message)

	// Convert hash to scalar
	e := new(big.Int).SetBytes(h.Sum(nil))
	e.Mod(e, curve.Params().N) // reduce mod n

	return e
}
