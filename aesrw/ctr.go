package aesrw

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
)

const BlockSize = aes.BlockSize

type CTR [BlockSize]byte

func (c CTR) Add(n int64) CTR {
	if n < 0 {
		panic(fmt.Errorf("an negative: %d", n))
	}

	resInt := make([]int64, BlockSize)
	for i := 0; i < BlockSize; i++ {
		resInt[i] = int64(c[i])
	}
	resInt[BlockSize-1] += n
	for i := BlockSize - 1; i >= 0; i-- {
		if resInt[i] <= 0xFF {
			break
		}
		carry := resInt[i] >> 8
		remain := resInt[i] & 0xFF
		resInt[i] = remain
		if i != 0 {
			resInt[i-1] += carry
		}
	}

	res := CTR{}
	for i := 0; i < BlockSize; i++ {
		res[i] = byte(resInt[i] % 0xFF)
	}
	return res
}

func (c CTR) IV() []byte {
	return c[:]
}

func RandomCTR() (CTR, error) {
	res := CTR{}
	_, err := rand.Read(res[:])
	return res, err
}
