package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// ParsePublicKey 从字节数组中解析出 public key
func ParsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return pub, nil
}

// ParsePrivateKey 从字节数组中解析出 private key,可解析 pkcs1,pkcs8 两种格式
// block.Type : PRIVATE KEY pkcs8
// block.Type : RSA PRIVATE KEY pkcs1
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("private key error")
	}

	switch block.Type {
	case "PRIVATE KEY": // pkcs8
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		} else {
			return key.(*rsa.PrivateKey), nil
		}

	case "RSA PRIVATE KEY": // pkcs1
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, errors.New("unknown type of private key")
	}
}

func rsaHash() crypto.Hash {
	return crypto.SHA1
}

// PrivateKeySign 用私钥对数据进行签名
func PrivateKeySign(data []byte, hashFunc crypto.Hash, privateKey *rsa.PrivateKey) ([]byte, error) {
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, hashFunc, digest)
}

// PublicKeyVerify 用公钥对相应私钥签名的数据进行验签
func PublicKeyVerify(sign, data []byte, hashFunc crypto.Hash, publicKey *rsa.PublicKey) error {
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey, hashFunc, digest, sign)
}

// PublicKeyEncrypt 用公钥对数据进行加密
func PublicKeyEncrypt(data []byte, publkcKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publkcKey, data)
}

// PrivateKeyDecrypt 用私钥对数据做解密
func PrivateKeyDecrypt(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
}
