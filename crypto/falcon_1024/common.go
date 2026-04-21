package falcon

import (
	"fmt"

	"golang.org/x/crypto/sha3"
)

const (
	rejectionThreshold = 5 * modulusQ
	l2bound            = 70265242
)

func hashToPointVartime(sc sha3.ShakeHash) (coeffPoly, error) {
	out := make(coeffPoly, polyDegree)
	written := 0
	n := polyDegree
	var buf [2]byte
	for n > 0 {
		_, err := sc.Read(buf[:])
		if err != nil {
			return nil, fmt.Errorf("hashToPointVartime: %w", err)
		}
		w := (uint32(buf[0]) << 8) | uint32(buf[1])
		if w < rejectionThreshold {
			for w >= modulusQ {
				w -= modulusQ
			}
			out[written] = int32(w)
			n--
		}
	}

	return out, nil
}

func hashToPointCT(sc sha3.ShakeHash, tmp []uint16) (coeffPoly, error) {
	// TODO
	return nil, nil
}

func isShort(s1, s2 coeffPoly) bool {
	var s uint32
	var ng uint32
	for i := range polyDegree {
		z := s1[i]
		s += uint32(z * z)
		ng |= s
		z = s2[i]
		s += uint32(z * z)
		ng |= s
	}
	s |= -(ng >> 31)

	return s <= l2bound
}

func isShortHalf(sqn uint32, s2 coeffPoly) bool {
	ng := -(sqn >> 31)
	for i := range polyDegree {
		z := s2[i]
		sqn += uint32(z * z)
		ng |= sqn
	}
	sqn |= -(ng >> 31)

	return sqn <= l2bound
}
