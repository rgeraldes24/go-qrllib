package falcon

const ffLDLTreeSize = 11264

func ffLDLBinaryNormalize(tree fprPoly, origLogPolyDegree int, logPolyDegree int) {
	if logPolyDegree == 1 {
		tree[0] = fprMul(fprSqr(tree[0]), fprInvSigma[origLogPolyDegree])
	} else {
		ffLDLBinaryNormalize(tree[polyDegree:], origLogPolyDegree, logPolyDegree-1)
		ffLDLBinaryNormalize(tree[polyDegree+ffLDLTreeSize(polyDegree-1)], origLogPolyDegree, logPolyDegree-1) // TODO logpolydegree
	}
}

func ffLDLFFTInner(tree, g0, g1 fprPoly, logn int) {
	tmp := make(fprPoly, polyDegree)

	polyLDLMvFFT(tmp, tree, g0, g1, g0)

	polySplitFFT(g1, g1[hn:], g0)
	polySplitFFT(g0, g0[hn:], g0)

	ffLDLFFTInner(tree[polyDegree:], g1, g1[hn:], logPolyDegree-1)
	ffLDLFFTInner(tree[polyDegree:], g0, g0[hn:], logPolyDegree-1)
}

func ffLDLFFT(tree, g00, g01, g11 fprPoly) {
	d00 := make(fprPoly, polyDegree)
	d11 := make(fprPoly, polyDegree)

	copy(d00, g00)
	polyLDLMvFFT(d11, tree, g00, g01, g11)

	d00Lo := make(fprPoly, hn)
	d00Hi := make(fprPoly, hn)
	d11Lo := make(fprPoly, hn)
	d11Hi := make(fprPoly, hn)

	polySplitFFT(d00Lo, d00Hi, d00)
	polySplitFFT(d11Lo, d11Hi, d11)

	ffLDLFFTInner(tree[polyDegree:polyDegree+ffLDLTreeSize], d00Lo, d00Hi, polyDegree-1)
	ffLDLFFTInner(tree[polyDegree+ffLDLTreeSize:polyDegree+2*ffLDLTreeSize], d11Lo, d11Hi, polyDegree-1)
}

func smallIntsToFPR(dst fprPoly, src coeffPoly) {
	for i := range polyDegree {
		dst[i] = fprOf(src[i])
	}
}

func expandPrivateKey(f, g, ntruF, ntruG coeffPoly) *ExpandedPrivateKey {
	esk := &ExpandedPrivateKey{
		b00:  make(fprPoly, polyDegree),
		b01:  make(fprPoly, polyDegree),
		b10:  make(fprPoly, polyDegree),
		b11:  make(fprPoly, polyDegree),
		tree: make(fprPoly, ffLDLTreeSize),
	}

	rf := esk.b01
	rg := esk.b00
	rNtruF := esk.b11
	rNtruG := esk.b10

	smallIntsToFPR(rf, f)
	smallIntsToFPR(rg, g)
	smallIntsToFPR(rNtruF, ntruF)
	smallIntsToFPR(rNtruG, ntruG)

	fft(rf)
	fft(rg)
	fft(rNtruF)
	fft(rNtruG)
	polyNeg(rf)
	polyNeg(rNtruF)

	g00 := make(fprPoly, polyDegree)
	g01 := make(fprPoly, polyDegree)
	g11 := make(fprPoly, polyDegree)
	gxx := make(fprPoly, polyDegree)

	copy(g00, esk.b00)
	polyMulSelfAdjFFT(g00)
	copy(gxx, esk.b01)
	polyMulSelfAdjFFT(gxx)
	polyAdd(g00, gxx)

	copy(g01, esk.b00)
	polyMulAdjFFT(g01, esk.b01)
	copy(gxx, esk.b01)
	polyMulAdjFFT(gxx, esk.b11)
	polyAdd(g01, gxx)

	copy(g11, esk.b10)
	polyMulSelfAdjFFT(g11)
	copy(gxx, esk.b11)
	polyMulSelfAdjFFT(gxx)
	polyAdd(g11, gxx)

	ffLDLFFT(esk.tree, g00, g01, g11)

	ffLDLBinaryNormalize(esk.tree, logPolyDegree, logPolyDegree)

	return esk
}

func signTree(esk *ExpandedPrivateKey, hm coeffPoly) (coeffPoly, error) {
	return nil, nil
}
