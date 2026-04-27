package falcon

const (
	hn = polyDegree >> 1
	qn = hn >> 1
)

func fpcAdd(aRe, aIm, bRe, bIm fpr) (fpr, fpr) {
	return fprAdd(aRe, bRe), fprAdd(aIm, bIm)
}

func fpcSub(aRe, aIm, bRe, bIm fpr) (fpr, fpr) {
	return fprSub(aRe, bRe), fprSub(aIm, bIm)

}

func fpcMul(aRe, aIm, bRe, bIm fpr) (fpr, fpr) {
	return fprSub(fprMul(aRe, bRe), fprMul(aIm, bIm)),
		fprAdd(fprMul(aRe, bIm), fprMul(aIm, bRe))
}

func fpcDiv(aRe, aIm, bRe, bIm fpr) (fpr, fpr) {
	fpctM := fprAdd(fprSqr(bRe), fprSqr(bIm))
	fpctM = fprInv(fpctM)
	fpctBRe := fprMul(bRe, fpctM)
	fpctBIm := fprMul(fprNeg(bIm), fpctM)
	fpctDRe := fprSub(fprMul(aRe, fpctBRe), fprMul(aIm, fpctBIm))
	fpctDIm := fprAdd(fprMul(aRe, fpctBIm), fprMul(aIm, fpctBRe))
	return fpctDRe, fpctDIm
}

func polyInvNorm2FFT(d, a, b fprPoly) {
	for u := range hn {
		aRe := a[u]
		aIm := a[u+hn]
		bRe := b[u]
		bIm := b[u+hn]
		d[u] = fprInv(fprAdd(
			fprAdd(fprSqr(aRe), fprSqr(aIm)),
			fprAdd(fprSqr(bRe), fprSqr(bIm)),
		))
	}
}

func polyAdjFFT(a fprPoly) {
	for u := (polyDegree >> 1); u < polyDegree; u++ {
		a[u] = fprNeg(a[u])
	}
}

func polyMulAutoAdjFFT(a, b fprPoly) {
	for u := range hn {
		a[u] = fprMul(a[u], b[u])
		a[u+hn] = fprMul(a[u+hn], b[u])
	}
}

func polyMulSelfAdjFFT(a fprPoly) {
	for u := range hn {
		aRe := a[u]
		aIm := a[u+hn]
		a[u] = fprAdd(fprSqr(aRe), fprSqr(aIm))
		a[u+hn] = fprZero
	}
}

func polyMulAdjFFT(a, b fprPoly) {
	for u := range hn {
		aRe := a[u]
		aIm := a[u+hn]
		bRe := b[u]
		bIm := fprNeg(b[u+hn])
		a[u], a[u+hn] = fpcMul(aRe, aIm, bRe, bIm) // TODO
	}
}

func polyMulConst(a fprPoly, x fpr) {
	for u := range polyDegree {
		a[u] = fprMul(a[u], x)
	}
}

func polyLDLMvFFT(d11, l10, g00, g01, g11 fprPoly) {}

func polySplitFFT(f0, f1, f fprPoly) {
	f0[0] = f[0]
	f1[0] = f[hn]

	for u := 0; u < qn; u++ {
		aRe := f[(u<<1)+0]
		aIm := f[(u<<1)+0+hn]
		bRe := f[(u<<1)+1]
		bIm := f[(u<<1)+1+hn]

		tRe, tIm := fpcAdd(aRe, aIm, bRe, bIm)
		f0[u] = fprHalf(tRe)
		f0[u+qn] = fprHalf(tIm)

		tRe, tIm = fpcSub(aRe, aIm, bRe, bIm)
		tRe, tIm = fpcMul(tRe, tIm, fprGmTab[((u+hn)<<1)+0], fprNeg(fprGmTab[((u+hn)<<1)+1]))
		f1[u] = fprHalf(tRe)
		f1[u+qn] = fprHalf(tIm)
	}
}

func fft(f fprPoly) {
	t := polyDegree >> 1
	for u, m := 1, 2; u < logPolyDegree; u, m = u+1, m<<1 {
		ht := t >> 1
		hm := m >> 1
		for i1, j1 := 0, 0; i1 < hm; i1, j1 = i1+1, j1+t {
			j2 := j1 + ht
			sRe := fprGmTab[((m+i1)<<1)+0]
			sIm := fprGmTab[((m+i1)<<1)+1]
			for j := j1; j < j2; j++ {
				xRe := f[j]
				xIm := f[j+hn]
				yRe := f[j+ht]
				yIm := f[j+ht+hn]
				yRe, yIm = fpcMul(yRe, yIm, sRe, sIm)
				f[j], f[j+hn] = fpcAdd(xRe, xIm, yRe, yIm)
				f[j+ht], f[j+ht+hn] = fpcSub(xRe, xIm, yRe, yIm)
			}
		}
		t = ht
	}
}

func iftt(f fprPoly) {
	t := 1
	m := polyDegree
	for u := logPolyDegree; u > 1; u-- {
		hm := m >> 1
		dt := t << 1
		for i1, j1 := 0, 0; j1 < hn; i1, j1 = i1+1, j1+dt {
			j2 := j1 + t
			sre := fprGmTab[((hm+i1)<<1)+0]
			sim := fprNeg(fprGmTab[((hm+i1)<<1)+1])
			for j := j1; j < j2; j++ {
				xre := f[j]
				xim := f[j+hn]
				yre := f[j+t]
				yim := f[j+t+hn]
				f[j], f[j+hn] = fpcAdd(xre, xim, yre, yim)
				xre, xim = fpcSub(xre, xim, yre, yim)
				f[j+t], f[j+t+hn] = fpcMul(xre, xim, sre, sim)
			}
		}
		t = dt
		m = hm
	}

	for u := range polyDegree {
		f[u] = fprMul(f[u], fprP2)
	}
}

func polyAdd(a, b fprPoly) {
	for u := range polyDegree {
		a[u] = fprAdd(a[u], b[u])
	}
}

func polyNeg(a fprPoly) {
	for u := range polyDegree {
		a[u] = fprNeg(a[u])
	}
}
