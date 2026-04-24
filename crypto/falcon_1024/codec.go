package falcon

import (
	"errors"
	"fmt"
)

const (
	maxCompMagnitude = 2047
	modQBits         = 14
	modulusQ         = 12289
	modQEncodedSize  = ((polyDegree * modQBits) + 7) >> 3
)

var (
	ErrModQEncodeDoesNotFit            = errors.New("mod-q encoding does not fit target length")
	ErrModQEncodeCoefficientOutOfRange = errors.New("mod-q coefficient exceeds supported range")
	ErrModQEncodeWrongCoefficientCount = errors.New("wrong number of mod-q coefficients")

	ErrModQDecodeInputTooShort         = errors.New("mod-q input is too short")
	ErrModQDecodeCoefficientOutOfRange = errors.New("mod-q input contains an out-of-range coefficient")
	ErrModQDecodeTrailingData          = errors.New("mod-q input contains trailing data")

	ErrCompEncodeDoesNotFit            = errors.New("compressed signature does not fit target length")
	ErrCompEncodeCoefficientOutOfRange = errors.New("signature coefficient exceeds supported compressed range")
	ErrCompEncodeWrongCoefficientCount = errors.New("wrong number of signature coefficients")

	ErrCompDecodeTruncated             = errors.New("encoded signature is truncated")
	ErrCompDecodeNegativeZero          = errors.New("encoded signature contains negative zero")
	ErrCompDecodeCoefficientOutOfRange = errors.New("encoded signature coefficient exceeds supported range")
	ErrCompDecodeTrailingData          = errors.New("encoded signature contains trailing data")

	ErrTrimInvalidBitWidth             = errors.New("trim invalid bit width")
	ErrTrimEncodeWrongCoefficientCount = errors.New("trim wrong coefficient count")
	ErrTrimEncodeCoefficientOutOfRange = errors.New("trim coefficient out of range")
	ErrTrimEncodeDoesNotFit            = errors.New("trim encoding does not fit target length")
	ErrTrimDecodeInputTooShort         = errors.New("trim input is too short")
	ErrTrimDecodeTrailingData          = errors.New("trim input contains trailing data")
	ErrTrimDecodeForbiddenValue        = errors.New("trim input contains a forbidden value")
)

func modQEncode(dst []byte, x mqPoly) (int, error) {
	if len(x) != polyDegree {
		return 0, fmt.Errorf("modQEncode: %w", ErrModQEncodeWrongCoefficientCount)
	}

	for _, xi := range x {
		if xi < 0 || xi >= modulusQ {
			return 0, fmt.Errorf("modQEncode: %w", ErrModQEncodeCoefficientOutOfRange)
		}
	}

	if modQEncodedSize > len(dst) {
		return 0, fmt.Errorf("modQEncode: %w", ErrModQEncodeDoesNotFit)
	}

	var acc uint32
	var accLen int
	written := 0

	for _, xi := range x {
		acc = (acc << modQBits) | uint32(xi)
		accLen += modQBits
		for accLen >= 8 {
			accLen -= 8
			dst[written] = byte(acc >> accLen)
			written++
		}
	}
	if accLen > 0 {
		dst[written] = byte(acc << (8 - accLen))
		written++
	}

	return written, nil
}

func modQDecode(src []byte) (mqPoly, int, error) {
	if len(src) < modQEncodedSize {
		return nil, 0, fmt.Errorf("modQDecode: %w", ErrModQDecodeInputTooShort)
	}

	out := make(mqPoly, polyDegree)
	var acc uint32
	var accLen int
	written := 0

	for _, b := range src[:modQEncodedSize] {
		acc = (acc << 8) | uint32(b)
		accLen += 8
		for accLen >= modQBits && written < polyDegree {
			accLen -= modQBits
			w := (acc >> accLen) & ((1 << modQBits) - 1)
			if w >= modulusQ {
				return nil, 0, fmt.Errorf("modQDecode: %w", ErrModQDecodeCoefficientOutOfRange)
			}
			out[written] = uint32(w)
			written++
		}
	}
	if accLen > 0 && (acc&((uint32(1)<<accLen)-1)) != 0 {
		return nil, 0, fmt.Errorf("modQDecode: %w", ErrModQDecodeTrailingData)
	}

	return out, modQEncodedSize, nil
}

func trimI16Encode(dst []byte, x coeffPoly, bits int) (int, error) {
	if bits <= 0 || bits > 16 {
		return 0, fmt.Errorf("trimI16Encode: %w", ErrTrimInvalidBitWidth)
	}

	n, err := trimEncode(dst, x, bits)
	if err != nil {
		return 0, fmt.Errorf("trimI16Encode: %w", err)
	}
	return n, nil
}

func trimI16Decode(src []byte, bits int) (coeffPoly, int, error) {
	if bits <= 0 || bits > 16 {
		return nil, 0, fmt.Errorf("trimI16Decode: %w", ErrTrimInvalidBitWidth)
	}

	x, n, err := trimDecode(src, bits)
	if err != nil {
		return nil, 0, fmt.Errorf("trimI16Decode: %w", err)
	}
	return x, n, nil
}

func trimI8Encode(dst []byte, x coeffPoly, bits int) (int, error) {
	if bits <= 0 || bits > 8 {
		return 0, fmt.Errorf("trimI8Encode: %w", ErrTrimInvalidBitWidth)
	}

	n, err := trimEncode(dst, x, bits)
	if err != nil {
		return 0, fmt.Errorf("trimI8Encode: %w", err)
	}
	return n, nil
}

func trimI8Decode(src []byte, bits int) (coeffPoly, int, error) {
	if bits <= 0 || bits > 8 {
		return nil, 0, fmt.Errorf("trimI8Decode: %w", ErrTrimInvalidBitWidth)
	}

	x, n, err := trimDecode(src, bits)
	if err != nil {
		return nil, 0, fmt.Errorf("trimI8Decode: %w", err)
	}
	return x, n, nil
}

func trimEncode(dst []byte, x coeffPoly, bits int) (int, error) {
	if bits <= 0 || bits > 16 {
		return 0, ErrTrimInvalidBitWidth
	}
	if len(x) != polyDegree {
		return 0, ErrTrimEncodeWrongCoefficientCount
	}

	maxv := int32((1 << (bits - 1)) - 1)
	for _, xi := range x {
		if xi < -maxv || xi > maxv {
			return 0, ErrTrimEncodeCoefficientOutOfRange
		}
	}

	if outLen := ((polyDegree * bits) + 7) >> 3; outLen > len(dst) {
		return 0, ErrTrimEncodeDoesNotFit
	}

	var acc uint32
	var accLen int
	mask := uint32((1 << bits) - 1)
	written := 0
	for _, xi := range x {
		acc = (acc << bits) | (uint32(xi) & mask)
		accLen += bits
		for accLen >= 8 {
			accLen -= 8
			dst[written] = byte(acc >> accLen)
			written++
		}
	}
	if accLen > 0 {
		dst[written] = byte(acc << (8 - accLen))
		written++
	}

	return written, nil
}

func trimDecode(src []byte, bits int) (coeffPoly, int, error) {
	if bits <= 0 || bits > 16 {
		return nil, 0, ErrTrimInvalidBitWidth
	}
	inLen := ((polyDegree * bits) + 7) >> 3
	if inLen > len(src) {
		return nil, 0, ErrTrimDecodeInputTooShort
	}

	out := make(coeffPoly, polyDegree)
	var acc uint32
	var accLen int
	mask1 := uint32((1 << bits) - 1)
	mask2 := uint32(1 << (bits - 1))
	read := 0
	written := 0

	for read < inLen {
		acc = (acc << 8) | uint32(src[read])
		read++
		accLen += 8

		for accLen >= bits && written < polyDegree {
			accLen -= bits
			w := (acc >> accLen) & mask1
			if w&mask2 != 0 {
				w |= ^mask1
			}
			if int32(w) == -int32(mask2) {
				return nil, 0, ErrTrimDecodeForbiddenValue
			}
			out[written] = int32(w)
			written++
		}
	}

	if accLen > 0 && (acc&((uint32(1)<<accLen)-1)) != 0 {
		return nil, 0, ErrTrimDecodeTrailingData
	}

	return out, read, nil
}

func compEncode(dst []byte, x coeffPoly) (int, error) {
	if len(x) != polyDegree {
		return 0, fmt.Errorf("compEncode: %w", ErrCompEncodeWrongCoefficientCount)
	}

	for _, xi := range x {
		if xi < -maxCompMagnitude || xi > maxCompMagnitude {
			return 0, fmt.Errorf("compEncode: %w", ErrCompEncodeCoefficientOutOfRange)
		}
	}

	var acc uint32
	var accLen int
	written := 0

	for _, xi := range x {
		t := xi
		b := uint32(0)
		if t < 0 {
			t = -t
			b = 0x80
		}
		b |= uint32(t) & 0x7f
		high := int(t) >> 7

		acc = (acc << 8) | b
		accLen += 8

		acc = (acc << (high + 1)) | 1
		accLen += high + 1

		for accLen >= 8 {
			accLen -= 8
			if written >= len(dst) {
				return 0, fmt.Errorf("compEncode: %w", ErrCompEncodeDoesNotFit)
			}
			dst[written] = byte(acc >> accLen)
			written++
		}
	}

	if accLen > 0 {
		if written >= len(dst) {
			return 0, fmt.Errorf("compEncode: %w", ErrCompEncodeDoesNotFit)
		}
		dst[written] = byte(acc << (8 - accLen))
		written++
	}

	return written, nil
}

func compDecode(src []byte) (coeffPoly, int, error) {
	out := make(coeffPoly, polyDegree)
	var acc uint32
	var accLen int
	written := 0

	for i := range polyDegree {
		if written >= len(src) {
			return nil, 0, fmt.Errorf("compDecode: %w", ErrCompDecodeTruncated)
		}

		acc = (acc << 8) | uint32(src[written])
		written++

		b := acc >> accLen
		signBit := b & 0x80
		mag := int32(b & 0x7F)

		for {
			if accLen == 0 {
				if written >= len(src) {
					return nil, 0, fmt.Errorf("compDecode: %w", ErrCompDecodeTruncated)
				}
				acc = (acc << 8) | uint32(src[written])
				written++
				accLen = 8
			}
			accLen--
			if ((acc >> accLen) & 1) != 0 {
				break
			}
			mag += 128
			if mag > maxCompMagnitude {
				return nil, 0, fmt.Errorf("compDecode: %w", ErrCompDecodeCoefficientOutOfRange)
			}
		}

		if signBit != 0 && mag == 0 {
			return nil, 0, fmt.Errorf("compDecode: %w", ErrCompDecodeNegativeZero)
		}

		if signBit != 0 {
			mag = -mag
		}
		out[i] = mag
	}

	if accLen > 0 && (acc&((uint32(1)<<accLen)-1)) != 0 {
		return nil, 0, fmt.Errorf("compDecode: %w", ErrCompDecodeTrailingData)
	}

	return out, written, nil
}
