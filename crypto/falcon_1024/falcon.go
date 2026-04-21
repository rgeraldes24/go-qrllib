package falcon

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/sha3"
)

const (
	PrivateKeySize      = 2305
	PublicKeySize       = 1793
	SeedSize            = 48
	PaddedSignatureSize = 1280
	CTSignatureSize     = 1577

	keygenTemp10Fpr = 3584

	signatureCompressed signatureType = 1
	signaturePadded     signatureType = 2
	signatureCT         signatureType = 3
)

var (
	ErrExpandPrivKeyInvalidFormat = errors.New("invalid expanded private key format")
	ErrInvalidSeedSize            = errors.New("invalid seed size")
)

type signatureType byte

type CompressedSignature []byte

type PaddedSignature [PaddedSignatureSize]byte

type CTSignature [CTSignatureSize]byte

type PrivateKey [PrivateKeySize]byte

type ExpandedPrivateKey struct {
	f     coeffPoly
	g     coeffPoly
	ntruF coeffPoly
	ntruG coeffPoly
}

func (sk *ExpandedPrivateKey) Sign(msg []byte) (CompressedSignature, error) {
	// tree path
	return CompressedSignature{}, nil
}

type PublicKey [PublicKeySize]byte

type decodedPublicKey struct{ h mqPoly }

type Seed [SeedSize]byte

func NewSeed() (Seed, error) {
	var seed Seed
	_, err := rand.Read(seed[:])
	return seed, err
}

func SeedFromBytes(src []byte) (Seed, error) {
	if len(src) != SeedSize {
		return Seed{}, ErrInvalidSeedSize
	}
	var seed Seed
	copy(seed[:], src)
	return seed, nil
}

func KeyGen() (PrivateKey, PublicKey, error) {
	seed, err := NewSeed()
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	sk, pk, err := keyGenFromSeed(seed)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	return sk, pk, nil
}

func KeyGenFromSeed(seed Seed) (PrivateKey, PublicKey, error) {
	sk, pk, err := keyGenFromSeed(seed)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	return sk, pk, nil
}

type keygenWorkspace struct {
	fpr []fpr
	mq  mqPoly
}

func newKeygenWorkspace() *keygenWorkspace {
	return &keygenWorkspace{
		fpr: make([]fpr, keygenTemp10Fpr),
		mq:  make(mqPoly, polyDegree),
	}
}

func keyGenFromSeed(seed Seed) (PrivateKey, PublicKey, error) {
	rng := sha3.NewShake256()
	if _, err := rng.Write(seed[:]); err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	wk := newKeygenWorkspace()
	esk, dpk, err := keygen(rng, wk)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	sk, err := encodePrivateKey(esk)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	pk, err := encodePublicKey(dpk)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	return sk, pk, nil
}

func Sign(sk PrivateKey, msg []byte) (CompressedSignature, error) { // dynamic path
	esk, err := expandPrivKey(sk, tmp)
	if err != nil {
		return nil, err
	}
}

func encodePrivateKey(ExpandedPrivateKey)

func SignPadded(sk PrivateKey, msg []byte) (PaddedSignature, error) {}

func SignCT(sk PrivateKey, msg []byte) (CTSignature, error) {}

func ExpandPrivateKey(sk PrivateKey, tmp []fpr) (*ExpandedPrivateKey, error) {
	if (sk[0] & 0xF0) != 0x50 {
		return expandedPrivateKey{}, ErrExpandPrivKeyInvalidFormat
	}

	if logn := sk[0] & 0x0F; logn != logPolyDegree {
		return expandedPrivateKey{}, ErrExpandPrivKeyInvalidFormat
	}

	return expandedPrivateKey{}, nil
}

func signTreeFinish(
	rng sha3.ShakeHash,
	sigType SignatureType,
	sk expandedPrivateKey,
	hashData sha3.ShakeHash,
	nonce [40]byte,
	tmp []fpr,
) ([]byte, error)

func signDyn(sk expandedPrivateKey, hm coeffPoly, tmp []fpr) (coeffPoly, error) {}

func signTree(sk expandedPrivateKey, hm coeffPoly, tmp []fpr) (coeffPoly, error) {}

func verifyStart(sig []byte) (sha3.ShakeHash, error) {
	hd := sha3.NewShake256()
	if _, err := hd.Write(seed[:]); err != nil {
		return false, err
	}
}

func verifyFinish(sig []byte, sigType int, pubkey PublicKey, hashData sha3.ShakeHash) (bool, error) {}

func Verify(sig CompressedSignature, pk PublicKey, msg []byte) (bool, error) {
	hd, err := verifyStart(sig)
	if err != nil {
		return false, err
	}

	ok, err := verifyFinish(sig, pubkey, hd)
	if err != nil {
		return false, err
	}

	return ok, nil
}

func VerifyPadded(sig PaddedSignature, pk PublicKey, msg []byte) (bool, error) {}

func VerifyCT(sig CTSignature, pk PublicKey, msg []byte) (bool, error) {}
