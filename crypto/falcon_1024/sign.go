package falcon

const ffLDLTreeSize = 11264

func ffLDLBinaryNormalize(tree fprPoly, logn int) {}

func smallIntsToFPR(dst fprPoly, src coeffPoly) {
	for u := 0; u < polyDegree; u++ {
		dst[u] = fprOf(t[u])
	}
}

func expandPrivateKey(esk *ExpandedPrivateKey, f, g, ntruF, ntruG coeffPoly, tmp []fpr) error {
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
}
