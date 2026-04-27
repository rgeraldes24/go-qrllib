package falcon

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"
)

const (
	PrivateKeySize      = 2305
	PublicKeySize       = 1793
	SeedSize            = 48
	PaddedSignatureSize = 1280

	privateKeySmallCoeffBits = 5
	privateKeyNtruFBits      = 8

	publicKeyHeader       byte = 0x00 + logPolyDegree
	signaturePaddedHeader byte = 0x30 + logPolyDegree
	privateKeyHeader      byte = 0x50 + logPolyDegree

	keygenTemp10Fpr  = 3584
	signDynTemp10Fpr = 9984

	encodedHeaderSize   = 1
	nonceSize           = 40
	signaturePrefixSize = encodedHeaderSize + nonceSize
)

var (
	ErrExpandPrivKeyInvalidFormat = errors.New("invalid expanded private key format")
	ErrInvalidSeedSize            = errors.New("invalid seed size")
	ErrEncodePrivateKeyWrongSize  = errors.New("encoded private key has wrong size")
	ErrEncodePublicKeyWrongSize   = errors.New("encoded public key has wrong size")
	ErrInvalidSignatureFormat     = errors.New("invalid signature format")
	ErrInvalidPublicKeyFormat     = errors.New("invalid public key format")
)

type PaddedSignature [PaddedSignatureSize]byte

type ExpandedPrivateKey struct {
	b00  fprPoly
	b01  fprPoly
	b10  fprPoly
	b11  fprPoly
	tree fprPoly
}

func (epk *ExpandedPrivateKey) Sign(random io.Reader, message []byte) (PaddedSignature, error) {
	return SignExpanded(random, epk, message)
}

type PrivateKey [PrivateKeySize]byte

func (priv PrivateKey) Public() (PublicKey, error) {
	return makePublic(priv)
}

func (priv PrivateKey) Sign(random io.Reader, message []byte) (PaddedSignature, error) {
	return Sign(random, priv, message)
}

func (priv PrivateKey) Expand() (*ExpandedPrivateKey, error) {
	return expandPriv(priv)
}

type PublicKey [PublicKeySize]byte

type decodedPublicKey struct{ h mqPoly }

type Seed [SeedSize]byte

func NewSeed(random io.Reader) (Seed, error) {
	if random == nil {
		random = rand.Reader
	}

	var seed Seed
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return Seed{}, err
	}

	return seed, nil
}

func SeedFromBytes(src []byte) (Seed, error) {
	if len(src) != SeedSize {
		return Seed{}, ErrInvalidSeedSize
	}
	var seed Seed
	copy(seed[:], src)
	return seed, nil
}

func GenerateKey(random io.Reader) (PublicKey, PrivateKey, error) {
	seed, err := NewSeed(random)
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}

	sk, pk, err := keyGenFromSeed(seed)
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}

	return pk, sk, nil
}

func NewKeyFromSeed(seed Seed) (PrivateKey, error) {
	privateKey := make([]byte, PrivateKeySize)
	newKeyFromSeed(privateKey, seed)
	return privateKey

	/*
		sk, pk, err := keyGenFromSeed(seed)
		if err != nil {
			return PrivateKey{}, PublicKey{}, err
		}

		return sk, pk, nil
	*/
}

func newKeyFromSeed(privateKey, seed []byte) error {
	k, err := newPrivateKeyFromSeed(seed)
	if err != nil {
		panic("")
	}
	copy(privateKey, k)
}

func newPrivateKeyFromSeed() {}

func keyGenFromSeed(seed Seed) (PrivateKey, PublicKey, error) {
	rng := sha3.NewShake256()
	if _, err := rng.Write(seed[:]); err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	esk, dpk, err := keygen(rng)
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

// encodePrivateKey serializes Falcon-1024 private key fields f, g, and F.
func encodePrivateKey(esk ExpandedPrivateKey) (PrivateKey, error) {
	sk := PrivateKey{privateKeyHeader}
	offset := 1

	written, err := trimI8Encode(sk[offset:], esk.f, privateKeySmallCoeffBits)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("encodePrivateKey f: %w", err)
	}
	offset += written

	written, err = trimI8Encode(sk[offset:], esk.g, privateKeySmallCoeffBits)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("encodePrivateKey g: %w", err)
	}
	offset += written

	written, err = trimI8Encode(sk[offset:], esk.ntruF, privateKeyNtruFBits)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("encodePrivateKey ntruF: %w", err)
	}
	offset += written

	if offset != PrivateKeySize {
		return PrivateKey{}, ErrEncodePrivateKeyWrongSize
	}

	return sk, nil
}

// encodePublicKey serializes the Falcon-1024 public polynomial h.
func encodePublicKey(dpk decodedPublicKey) (PublicKey, error) {
	pk := PublicKey{publicKeyHeader}

	written, err := modQEncode(pk[encodedHeaderSize:], dpk.h)
	if err != nil {
		return PublicKey{}, fmt.Errorf("encodePublicKey h: %w", err)
	}
	if written != PublicKeySize-encodedHeaderSize {
		return PublicKey{}, ErrEncodePublicKeyWrongSize
	}

	return pk, nil
}

func makePublic(sk PrivateKey) (PublicKey, error) {
	if len(sk) != PrivateKeySize {
		// TODO: return err
	}

	if sk[0] != privateKeyHeader {
		// TODO: return err
	}

	// TODO: maybe re use some parts of decode private key
	f := make(coeffPoly, polyDegree) // TODO: create newCoeffPoly
	offset := 1
	f, written, err := trimI8Decode(sk[offset:], privateKeySmallCoeffBits)
	if err != nil {
		return PublicKey{}, err
	}
	offset += written

	g, written, err = trimI8Decode(sk[offset:], privateKeySmallCoeffBits)
	if err != nil {
		return PublicKey{}, err
	}

	h := make(mqPoly, polyDegree)
	if err := computePublic(h, f, g); err != nil {
		return PublicKey{}, err
	}

	pk, err := encodePublicKey(decodedPublicKey{h})
	if err != nil {
		return PublicKey{}, err
	}

	return pk, nil
}

func signStart(random io.Reader) ([nonceSize]byte, sha3.ShakeHash, error) {
	if random == nil {
		random = rand.Reader
	}

	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return [nonceSize]byte{}, nil, err
	}

	hashData := sha3.NewShake256()
	if _, err := hashData.Write(nonce[:]); err != nil {
		return [nonceSize]byte{}, nil, err
	}

	return nonce, hashData, nil
}

func signDynFinish(
	sk PrivateKey,
	hashData sha3.ShakeHash,
	nonce [nonceSize]byte,
) (PaddedSignature, error) {
	return PaddedSignature{}, nil
}

func decodePrivateKey(sk PrivateKey) (coeffPoly, coeffPoly, coeffPoly, error) {
	return nil, nil, nil, nil
}

func expandPriv(sk PrivateKey) (*ExpandedPrivateKey, error) {
	if sk[0] != privateKeyHeader {
		return &ExpandedPrivateKey{}, ErrExpandPrivKeyInvalidFormat
	}

	f, g, ntruF, err := decodePrivateKey(sk)
	if err != nil {
		return &ExpandedPrivateKey{}, err
	}

	ntruG, err := completePrivate(f, g, ntruF, nil)
	if err != nil {
		return &ExpandedPrivateKey{}, err
	}

	expkey := expandPrivateKey(f, g, ntruF, ntruG)

	return expkey, nil
}

func signTreeFinish(
	esk *ExpandedPrivateKey,
	hashData sha3.ShakeHash,
	nonce [nonceSize]byte,
) (PaddedSignature, error) {
	hm, err := hashToPointVartime(hashData)
	if err != nil {
		return PaddedSignature{}, nil
	}

	sv, err := signTree(esk, hm)
	if err != nil {
		return PaddedSignature{}, err
	}

	sig := PaddedSignature{}
	sig[0] = signaturePaddedHeader

	_, err = compEncode(sig[signaturePrefixSize:], sv)
	if err != nil {
		return PaddedSignature{}, err
	}

	return sig, nil
}

func Sign(random io.Reader, sk PrivateKey, msg []byte) (PaddedSignature, error) { // dynamic path
	nonce, hashData, err := signStart(random)
	if err != nil {
		return PaddedSignature{}, nil
	}

	_, err = hashData.Write(msg)
	if err != nil {
		return PaddedSignature{}, err
	}

	sig, err := signDynFinish(sk, hashData, nonce)
	if err != nil {
		return PaddedSignature{}, err
	}

	return PaddedSignature(sig), nil
}

func SignExpanded(random io.Reader, esk *ExpandedPrivateKey, msg []byte) (PaddedSignature, error) {
	nonce, hashData, err := signStart(random)
	if err != nil {
		return PaddedSignature{}, nil
	}

	_, err = hashData.Write(msg)
	if err != nil {
		return PaddedSignature{}, err
	}

	sig, err := signTreeFinish(esk, hashData, nonce)
	if err != nil {
		return PaddedSignature{}, err
	}

	return sig, nil
}

func decodePublicKey(pubkey PublicKey) (decodedPublicKey, error) {
	h, _, err := modQDecode(pubkey[encodedHeaderSize:])
	if err != nil {
		return decodedPublicKey{}, err
	}

	return decodedPublicKey{h}, nil
}

func decodeSignature(sig []byte) (coeffPoly, error) {
	if len(sig) < signaturePrefixSize {
		return nil, ErrInvalidSignatureFormat
	}

	payload := sig[signaturePrefixSize:]

	dsig, read, err := compDecode(payload)
	if err != nil {
		return nil, err
	}

	if read == 0 {
		return nil, ErrInvalidSignatureFormat
	}

	if (signaturePrefixSize + read) != len(sig) {
		for (signaturePrefixSize + read) < len(sig) {
			if sig[signaturePrefixSize+read] != 0 {
				return nil, ErrInvalidSignatureFormat
			}
			read++
		}
	}

	return dsig, nil
}

// TODO: similar path to SignExpanded?
func Verify(sig PaddedSignature, pk PublicKey, msg []byte) (bool, error) {
	if pk[0] != publicKeyHeader {
		return false, ErrInvalidPublicKeyFormat
	}

	if sig[0] != signaturePaddedHeader {
		return false, ErrInvalidSignatureFormat
	}

	hashData := sha3.NewShake256()
	if _, err := hashData.Write(sig[encodedHeaderSize:signaturePrefixSize]); err != nil {
		return false, err
	}
	if _, err := hashData.Write(msg); err != nil {
		return false, err
	}

	dpk, err := decodePublicKey(pk)
	if err != nil {
		return false, err
	}

	dsig, err := decodeSignature(sig[:])
	if err != nil {
		return false, err
	}

	point, err := hashToPointVartime(hashData)
	if err != nil {
		return false, err
	}

	toNTTMonty(dpk.h)

	return verifyRaw(point, dsig, dpk.h, make(mqPoly, polyDegree)), nil
}
