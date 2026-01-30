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

//
//func (Impl) Sign(keyPair *KeyPair, message []byte, kEntropy []byte) (*Signature, error) {
//	curve := elliptic.P256()
//	k := new(big.Int).SetBytes(kEntropy)
//	k.Mod(x, curve.Params().N)
//
//	//   1. Pick random k
//	// already from parameters
//	//	2. R = k*G
//	RX, RY := curve.ScalarBaseMult(k.Bytes())
//	R := &Point{X: RX, Y: RY}
//
//	//   3. e = H(R || P || m)
//	e := computeE(R, keyPair.PublicKey, message)
//}

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
