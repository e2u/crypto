package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"strings"
)

var badCiphertextError error = errors.New("bad ciphertext")
var illegalArgumentError error = errors.New("Illegal Argument")
var notMultipleBlockError error = errors.New("ciphertext is not a multiple of the block size")
var badKeySizeError error = errors.New("error key size")

func srcPadding(name string, src []byte, blockSize int) []byte {
	padLen := blockSize
	if len(src)%blockSize != 0 {
		padLen = blockSize - len(src)%blockSize
	}
	return append(src, appPadding(name, padLen)...)
}

// 补位算法
// name 算法,len 补位长度
func appPadding(name string, l int) []byte {
	switch strings.ToLower(name) {
	case "pkcs5", "pkcs7", "pkcs5padding", "pkcs7padding":
		return bytes.Repeat([]byte{byte(l)}, l)
	case "iso10126", "iso10126padding":
		return func() []byte {
			rb := make([]byte, l)
			rand.Read(rb)
			rb[l-1] = byte(l)
			return rb
		}()
	case "ansix923":
		return func() []byte {
			rb := make([]byte, l)
			rb[l-1] = byte(l)
			return rb
		}()
	case "zeros", "zerospadding":
		return make([]byte, l)
	}
	return nil
}

// 移除补位
func unPadding(name string, src []byte) ([]byte, error) {
	switch strings.ToLower(name) {
	case "pkcs5", "pkcs7", "pkcs5padding", "pkcs7padding", "iso10126", "iso10126padding", "ansix923":
		return func() ([]byte, error) {
			l := len(src)
			last := int(src[l-1])
			if last > l {
				return nil, errors.New("padding error")
			}
			return src[:(l - last)], nil
		}()
	case "zeros", "zerospadding":
		return func() ([]byte, error) {
			for {
				if src[len(src)-1] != 0 {
					break
				}
				src = src[:len(src)-1]
			}
			return src, nil
		}()
	}
	return nil, errors.New("unsupport padding")
}

func genIV(s int) ([]byte, error) {
	iv := make([]byte, s)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

func ecbEnc(block cipher.Block, key, src []byte, padding string) ([]byte, error) {
	src = srcPadding(padding, src, block.BlockSize())
	dst := make([]byte, 0)
	tmp := make([]byte, block.BlockSize())
	for len(src) > 0 {
		block.Encrypt(tmp, src[:block.BlockSize()])
		src = src[block.BlockSize():]
		dst = append(dst, tmp...)
	}
	return dst, nil
}

func ecbDec(block cipher.Block, key, src []byte, padding string) ([]byte, error) {
	if len(src)%block.BlockSize() != 0 {
		return nil, notMultipleBlockError
	}

	// if len(src) <= block.BlockSize() {
	//     return nil, badCiphertextError
	// }

	dst := make([]byte, 0)
	tmp := make([]byte, block.BlockSize())

	for len(src) > 0 {
		block.Decrypt(tmp, src[:block.BlockSize()])
		src = src[block.BlockSize():]
		dst = append(dst, tmp...)
	}
	return unPadding(padding, dst)
}

// cfb 加密
func cfbEnc(block cipher.Block, key, iv, src []byte, padding string) ([]byte, error) {
	src = srcPadding(padding, src, block.BlockSize())
	dst := make([]byte, len(src))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

// cfb 解密
func cfbDec(block cipher.Block, key, iv, src []byte, padding string) ([]byte, error) {
	dst := make([]byte, len(src))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

// cbc 加密需要补位
func cbcEnc(block cipher.Block, key, iv, src []byte, padding string) ([]byte, error) {
	src = srcPadding(padding, src, block.BlockSize())
	dst := make([]byte, len(src))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, src)
	return dst, nil
}

// cbc 解密后需要去掉补位
func cbcDec(block cipher.Block, key, iv, src []byte, padding string) ([]byte, error) {
	if len(src)%block.BlockSize() != 0 {
		return nil, notMultipleBlockError
	}
	dst := make([]byte, len(src))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, src)
	return unPadding(padding, dst)
}

func ctrEnc(block cipher.Block, key, iv, src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

func ctrDec(block cipher.Block, key, iv, src []byte) ([]byte, error) {
	return ctrEnc(block, key, iv, src)
}

func ofbEnc(block cipher.Block, key, iv, src []byte, padding string) ([]byte, error) {
	src = srcPadding(padding, src, block.BlockSize())
	dst := make([]byte, len(src))
	cipher.NewOFB(block, iv).XORKeyStream(dst, src)
	return dst, nil
}

func ofbDec(block cipher.Block, key, iv, src []byte, padding string) ([]byte, error) {
	return ofbEnc(block, key, iv, src, "nopadding")
}

func MakeRandByte(l int) []byte {
	b := make([]byte, l)
	rand.Read(b)
	return b
}
