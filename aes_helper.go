package crypto

import (
	"crypto/aes"
	"fmt"
	"log"
	"strconv"
	"strings"
)

const debug = false

type AES struct {
	cipherName string
	keysize    int
	mode       string
	padding    string
}

// NewAES 返回 cipher 指定的算法,可以有以下组合
// 1. aes
// 2. 128,192,256
// 3. cbc,cfb,ctr,ofb
// 4. pkcs5,pkcs7,iso10126,ansix923,zeros,none
// 注: 只有cbc需要补位,cfb,ctr,ofb 都不需要补位
// 例如:
// aes-128-cbc-pkcs5
// aes-128-cbc-pkcs7
// aes-128-cfb
// aes-192-cfb
// aes-192-ctr
// aes-256-ofb
// 等组合
func NewAES(c string) AES {
	a := AES{cipherName: c}

	for i, c := range strings.Split(c, "-") {
		switch i {
		case 0:
			// aes
		case 1:
			//keysize
			keysize, _ := strconv.Atoi(c)
			a.keysize = keysize
		case 2:
			//mode
			a.mode = strings.ToLower(c)
		case 3:
			//padding
			a.padding = strings.ToLower(c)
		}
	}
	if debug {
		log.Printf("NewAES: %#v\n", a)
	}
	return a
}

// Encrypter 动态向量加密
func (a AES) Encrypter(key, src []byte) ([]byte, []byte, error) {
	iv, err := genIV(aes.BlockSize)
	if err != nil {
		return nil, nil, err
	}
	ent, err := a.EncrypterFixedIV(key, iv, src)
	if err != nil {
		return nil, nil, err
	}
	return ent, iv, err
}

// EncrypterMixIV 动态向量加密,IV 混在密文前返回
func (a AES) EncrypterMixIV(key, src []byte) ([]byte, error) {
	iv, err := genIV(aes.BlockSize)
	if err != nil {
		return nil, err
	}
	ent, err := a.EncrypterFixedIV(key, iv, src)
	if err != nil {
		return nil, err
	}
	return append(iv, ent...), err
}

// EncrypterFixedIV 指定初始向量的加密
func (a AES) EncrypterFixedIV(key, iv, src []byte) ([]byte, error) {
	if err := a.checkKeySize(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	switch a.mode {
	case "ecb":
		return ecbEnc(block, key, src, a.padding)
	case "cbc":
		return cbcEnc(block, key, iv, src, a.padding)
	case "cfb":
		return cfbEnc(block, key, iv, src, a.padding)
	case "ctr":
		return ctrEnc(block, key, iv, src)
	case "ofb":
		return ofbEnc(block, key, iv, src, a.padding)
	}
	return nil, illegalArgumentError
}

// DecrypterMixIV 动态向量解密,iv 是密文前 BlockSize 字节
func (a AES) DecrypterMixIV(key, src []byte) (out []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()
	out, err = a.DecrypterFixedIV(key, src[:aes.BlockSize], src[aes.BlockSize:])
	return out, err
}

// DecrypterFixedIV 指定初始向量的解密
func (a AES) DecrypterFixedIV(key, iv, src []byte) ([]byte, error) {

	if err := a.checkKeySize(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	switch a.mode {
	case "ecb":
		return ecbDec(block, key, src, a.padding)
	case "cbc":
		return cbcDec(block, key, iv, src, a.padding)
	case "cfb":
		return cfbDec(block, key, iv, src, a.padding)
	case "ctr":
		return ctrDec(block, key, iv, src)
	case "ofb":
		return ofbDec(block, key, iv, src, a.padding)
	}
	return nil, illegalArgumentError
}

func (a AES) checkKeySize(key []byte) error {
	if a.keysize != len(key)*8 {
		return badKeySizeError
	}
	return nil
}
