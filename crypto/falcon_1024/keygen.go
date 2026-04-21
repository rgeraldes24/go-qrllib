package falcon

import "golang.org/x/crypto/sha3"

const (
	maxFgBits           = 5
	fgRejectBound int32 = 1 << (maxFgBits - 1) // 16
	maxFgSqNorm         = 16823
)

func polySmallSqNorm(f coeffPoly) uint32 {
	return 0
}

func polySmallToFP(dst fprPoly, src coeffPoly) {

}

func solveNTRU(f, g coeffPoly, tmp []fpr) (coeffPoly, coeffPoly, error) {
	return coeffPoly{}, coeffPoly{}, nil
}

func polySmallMkGauss(rng sha3.ShakeHash, f coeffPoly) error {
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
	rt1 := tmp
	rt2 := rt1 + polyDegree
	rt3 := rt2 + polyDegree

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
