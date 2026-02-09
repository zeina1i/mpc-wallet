package schnorr

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

func randomEntropy(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGenerateKeyPair(t *testing.T) {
	impl := Impl{}
	curve := elliptic.P256()

	kp, err := impl.GenerateKeyPair(randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	if kp.PrivateKey == nil || kp.PrivateKey.Sign() == 0 {
		t.Fatal("private key should be non-zero")
	}
	if kp.PrivateKey.Cmp(curve.Params().N) >= 0 {
		t.Fatal("private key should be less than curve order")
	}
	if kp.PublicKey == nil || kp.PublicKey.X == nil || kp.PublicKey.Y == nil {
		t.Fatal("public key should not be nil")
	}
	if !curve.IsOnCurve(kp.PublicKey.X, kp.PublicKey.Y) {
		t.Fatal("public key should be on the curve")
	}
}

func TestGenerateKeyPairDeterministic(t *testing.T) {
	impl := Impl{}
	entropy := []byte("deterministic-seed-for-testing!!")

	kp1, err := impl.GenerateKeyPair(entropy)
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := impl.GenerateKeyPair(entropy)
	if err != nil {
		t.Fatal(err)
	}

	if kp1.PrivateKey.Cmp(kp2.PrivateKey) != 0 {
		t.Fatal("same entropy should produce the same private key")
	}
	if kp1.PublicKey.X.Cmp(kp2.PublicKey.X) != 0 || kp1.PublicKey.Y.Cmp(kp2.PublicKey.Y) != 0 {
		t.Fatal("same entropy should produce the same public key")
	}
}

func TestSign(t *testing.T) {
	impl := Impl{}
	curve := elliptic.P256()

	kp, err := impl.GenerateKeyPair(randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello schnorr")
	sig, err := impl.Sign(kp, msg, randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	if sig.R == nil || sig.R.X == nil || sig.R.Y == nil {
		t.Fatal("signature R point should not be nil")
	}
	if !curve.IsOnCurve(sig.R.X, sig.R.Y) {
		t.Fatal("signature R should be on the curve")
	}
	if sig.S == nil || sig.S.Sign() == 0 {
		t.Fatal("signature s should be non-zero")
	}
	if sig.S.Cmp(curve.Params().N) >= 0 {
		t.Fatal("signature s should be less than curve order")
	}
}

func TestSignDeterministic(t *testing.T) {
	impl := Impl{}
	entropy := []byte("deterministic-seed-for-testing!!")
	kEntropy := []byte("deterministic-nonce-for-testing!")

	kp, err := impl.GenerateKeyPair(entropy)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello schnorr")
	sig1, err := impl.Sign(kp, msg, kEntropy)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := impl.Sign(kp, msg, kEntropy)
	if err != nil {
		t.Fatal(err)
	}

	if sig1.R.X.Cmp(sig2.R.X) != 0 || sig1.R.Y.Cmp(sig2.R.Y) != 0 {
		t.Fatal("same inputs should produce the same R")
	}
	if sig1.S.Cmp(sig2.S) != 0 {
		t.Fatal("same inputs should produce the same s")
	}
}

func TestVerifyValidSignature(t *testing.T) {
	impl := Impl{}

	kp, err := impl.GenerateKeyPair(randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello schnorr")
	sig, err := impl.Sign(kp, msg, randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	if !impl.Verify(kp.PublicKey, msg, sig) {
		t.Fatal("valid signature should verify")
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	impl := Impl{}

	kp, err := impl.GenerateKeyPair(randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello schnorr")
	sig, err := impl.Sign(kp, msg, randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	if impl.Verify(kp.PublicKey, []byte("wrong message"), sig) {
		t.Fatal("signature should not verify with wrong message")
	}
}

func TestVerifyWrongPublicKey(t *testing.T) {
	impl := Impl{}

	kp, err := impl.GenerateKeyPair(randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	otherKp, err := impl.GenerateKeyPair(randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello schnorr")
	sig, err := impl.Sign(kp, msg, randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	if impl.Verify(otherKp.PublicKey, msg, sig) {
		t.Fatal("signature should not verify with wrong public key")
	}
}

func TestVerifyTamperedSignatureR(t *testing.T) {
	impl := Impl{}
	curve := elliptic.P256()

	kp, err := impl.GenerateKeyPair(randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello schnorr")
	sig, err := impl.Sign(kp, msg, randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with R by using a different random point
	tamperedR_x, tamperedR_y := curve.ScalarBaseMult(big.NewInt(42).Bytes())
	tampered := &Signature{
		R: &Point{X: tamperedR_x, Y: tamperedR_y},
		S: new(big.Int).Set(sig.S),
	}

	if impl.Verify(kp.PublicKey, msg, tampered) {
		t.Fatal("signature should not verify with tampered R")
	}
}

func TestVerifyTamperedSignatureS(t *testing.T) {
	impl := Impl{}

	kp, err := impl.GenerateKeyPair(randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello schnorr")
	sig, err := impl.Sign(kp, msg, randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	tampered := &Signature{
		R: sig.R,
		S: new(big.Int).Add(sig.S, big.NewInt(1)),
	}

	if impl.Verify(kp.PublicKey, msg, tampered) {
		t.Fatal("signature should not verify with tampered s")
	}
}

func TestComputeE_Consistency(t *testing.T) {
	curve := elliptic.P256()
	rx, ry := curve.ScalarBaseMult(big.NewInt(7).Bytes())
	px, py := curve.ScalarBaseMult(big.NewInt(13).Bytes())

	R := &Point{X: rx, Y: ry}
	P := &Point{X: px, Y: py}
	msg := []byte("test message")

	e1 := computeE(R, P, msg)
	e2 := computeE(R, P, msg)

	if e1.Cmp(e2) != 0 {
		t.Fatal("computeE should be deterministic")
	}
	if e1.Sign() == 0 {
		t.Fatal("e should be non-zero")
	}
	if e1.Cmp(curve.Params().N) >= 0 {
		t.Fatal("e should be less than curve order")
	}
}

func TestComputeE_DifferentInputs(t *testing.T) {
	curve := elliptic.P256()
	rx, ry := curve.ScalarBaseMult(big.NewInt(7).Bytes())
	px, py := curve.ScalarBaseMult(big.NewInt(13).Bytes())

	R := &Point{X: rx, Y: ry}
	P := &Point{X: px, Y: py}

	e1 := computeE(R, P, []byte("message A"))
	e2 := computeE(R, P, []byte("message B"))

	if e1.Cmp(e2) == 0 {
		t.Fatal("different messages should produce different e values")
	}
}

func TestSignAndVerifyMultipleMessages(t *testing.T) {
	impl := Impl{}

	kp, err := impl.GenerateKeyPair(randomEntropy(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	messages := [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("hello world"),
		make([]byte, 1024), // large message
	}

	for _, msg := range messages {
		sig, err := impl.Sign(kp, msg, randomEntropy(t, 32))
		if err != nil {
			t.Fatalf("Sign failed for message %q: %v", msg, err)
		}
		if !impl.Verify(kp.PublicKey, msg, sig) {
			t.Fatalf("Verify failed for message %q", msg)
		}
	}
}
