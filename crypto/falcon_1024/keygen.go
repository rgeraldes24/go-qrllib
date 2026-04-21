package falcon

import (
	"encoding/binary"
	"io"

	"golang.org/x/crypto/sha3"
)

const (
	maxFgBits               = 5
	fgRejectBound     int32 = 1 << (maxFgBits - 1) // 16
	maxFgSqNorm             = 16823
	maxSmallPolyCoeff       = 127
)

var gauss1024_12289 = [...]uint64{
	1283868770400643928, 6416574995475331444, 4078260278032692663,
	2353523259288686585, 1227179971273316331, 575931623374121527,
	242543240509105209, 91437049221049666, 30799446349977173,
	9255276791179340, 2478152334826140, 590642893610164,
	125206034929641, 23590435911403, 3948334035941,
	586753615614, 77391054539, 9056793210,
	940121950, 86539696, 7062824,
	510971, 32764, 1862,
	94, 4, 0,
}

func polySmallSqNorm(f coeffPoly) uint32 {
	return 0
}

func polySmallToFP(x fprPoly, f coeffPoly) {
	for u := range polyDegree {
		x[u] = fprOf(f[u])
	}
}

func solveNTRU(f, g coeffPoly, tmp []fpr) (coeffPoly, coeffPoly, error) {
	return coeffPoly{}, coeffPoly{}, nil
}

func readShakeU64(rng sha3.ShakeHash) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(rng, buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

// mkGauss
func sampleOneGaussian(rng sha3.ShakeHash) (int32, error) {
	r, err := readShakeU64(rng)
	if err != nil {
		return 0, err
	}

	neg := uint32(r >> 63)
	r &^= uint64(1) << 63
	f := uint32((r - gauss1024_12289[0]) >> 63)

	r, err = readShakeU64(rng)
	if err != nil {
		return 0, err
	}
	r &^= uint64(1) << 63
	var v uint32

	for k := uint32(1); k < uint32(len(gauss1024_12289)); k++ {
		t := uint32(((r - gauss1024_12289[k]) >> 63) ^ 1)
		v |= k & -(t & (f ^ 1))
		f |= t
	}

	v = (v ^ -neg) + neg

	return int32(v), nil
}

func polySmallMkGauss(rng sha3.ShakeHash, f coeffPoly) error {
	var parity int32

	for u := 0; u < polyDegree; {
		s, err := sampleOneGaussian(rng)
		if err != nil {
			return err
		}

		if s < -maxSmallPolyCoeff || s > maxSmallPolyCoeff {
			continue // retry same u
		}

		if u == (polyDegree - 1) {
			if (parity ^ (s & 1)) == 0 {
				continue
			}
		} else {
			parity ^= s & 1
		}

		f[u] = s
		u++
	}

	return nil
}

func sampleSmallPolys(rng sha3.ShakeHash, f, g coeffPoly) error {
	if err := polySmallMkGauss(rng, f); err != nil {
		return err
	}
	if err := polySmallMkGauss(rng, g); err != nil {
		return err
	}

	return nil
}

func rejectByRange(f, g coeffPoly) bool {
	for u := range polyDegree {
		if f[u] >= fgRejectBound || f[u] <= -fgRejectBound ||
			g[u] >= fgRejectBound || g[u] <= -fgRejectBound {
			return true
		}
	}
	return false
}

func rejectByNorm(f, g coeffPoly) bool {
	normF := polySmallSqNorm(f)
	normG := polySmallSqNorm(g)
	norm := (normF + normG) | -((normF | normG) >> 31)
	return norm > maxFgSqNorm
}

func rejectByOrthogonalNorm(f, g coeffPoly, tmp []fpr) bool {
	rt1 := fprPoly(tmp[:polyDegree])
	rt2 := fprPoly(tmp[polyDegree : 2*polyDegree])
	rt3 := fprPoly(tmp[2*polyDegree : 3*polyDegree])

	polySmallToFP(rt1, f)
	polySmallToFP(rt2, g)

	fft(rt1)
	fft(rt2)

	polyInvNorm2FFT(rt3, rt1, rt2)

	polyAdjFFT(rt1)
	polyAdjFFT(rt2)

	polyMulConst(rt1, fprQ)
	polyMulConst(rt2, fprQ)

	polyMulAutoAdjFFT(rt1, rt3)
	polyMulAutoAdjFFT(rt2, rt3)

	iftt(rt1)
	iftt(rt2)

	bnorm := fprZero
	for u := range polyDegree {
		bnorm = fprAdd(bnorm, fprSqr(rt1[u]))
		bnorm = fprAdd(bnorm, fprSqr(rt2[u]))
	}

	return !fprLt(bnorm, fprBnormMax)
}

func keygen(rng sha3.ShakeHash, wk *keygenWorkspace) (ExpandedPrivateKey, decodedPublicKey, error) {
	for {
		f := make(coeffPoly, polyDegree)
		g := make(coeffPoly, polyDegree)

		if err := sampleSmallPolys(rng, f, g); err != nil {
			return ExpandedPrivateKey{}, decodedPublicKey{}, err
		}

		if rejectByRange(f, g) {
			continue
		}

		if rejectByNorm(f, g) {
			continue
		}

		if rejectByOrthogonalNorm(f, g, wk.fpr) {
			continue
		}

		h, err := computePublic(f, g, wk.mq)
		if err != nil {
			continue
		}

		ntruF, ntruG, err := solveNTRU(f, g, wk.fpr)
		if err != nil {
			continue
		}

		return ExpandedPrivateKey{f, g, ntruF, ntruG}, decodedPublicKey{h}, nil
	}
}
