package crypto

import (
	"crypto/cipher"
	"crypto/des"
	"log"
	"strconv"
	"strings"
)

type DES struct {
	cipherName string
	keysize    int
	mode       string
	padding    string
	algorithm  string
}

// NewDES 返回 cipher 指定的算法,可以有以下组合
func NewDES(c string) DES {
	a := DES{cipherName: c}

	for i, c := range strings.Split(c, "-") {
		switch i {
		case 0:
			// 3des or des
			a.algorithm = strings.ToLower(c)
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
		log.Printf("NewDES: %#v\n", a)
	}
	return a
}

// Encrypter 动态向量加密
func (a DES) Encrypter(key, src []byte) ([]byte, []byte, error) {
	iv, err := genIV(des.BlockSize)
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
func (a DES) EncrypterMixIV(key, src []byte) ([]byte, error) {
	iv, err := genIV(des.BlockSize)
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
func (a DES) EncrypterFixedIV(key, iv, src []byte) ([]byte, error) {
	var err error
	var block cipher.Block

	if err = a.checkKeySize(key); err != nil {
		return nil, err
	}

	if a.algorithm == "3des" {
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = des.NewCipher(key)
	}

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
func (a DES) DecrypterMixIV(key, src []byte) ([]byte, error) {
	if len(src) < des.BlockSize*2 {
		return nil, badCiphertextError
	}
	return a.DecrypterFixedIV(key, src[:des.BlockSize], src[des.BlockSize:])
}

// DecrypterFixedIV 指定初始向量的解密
func (a DES) DecrypterFixedIV(key, iv, src []byte) ([]byte, error) {
	var err error
	var block cipher.Block

	if err = a.checkKeySize(key); err != nil {
		return nil, err
	}

	if a.algorithm == "3des" {
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = des.NewCipher(key)
	}

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

// des 密钥长度必须是 8的倍数
func (a DES) checkKeySize(key []byte) error {
	if a.keysize != len(key)*8 {
		return badKeySizeError
	}
	return nil
}
