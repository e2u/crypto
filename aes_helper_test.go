package crypto

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"testing"
)

const (
	showDebug = true
)

var key128 []byte = []byte("1234567890123456")
var key192 []byte = []byte("123456789012345678901234")
var key256 []byte = []byte("12345678901234567890123456789012")
var algos128 []string = []string{"aes-128-ecb-pkcs5", "aes-128-cbc-pkcs5", "aes-128-cbc-iso10126", "aes-128-cbc-ansix923", "aes-128-cbc-zeros", "aes-128-cfb", "aes-128-ctr", "aes-128-ofb"}
var algos192 []string = []string{"aes-192-ecb-pkcs5", "aes-192-cbc-pkcs5", "aes-192-cbc-iso10126", "aes-192-cbc-ansix923", "aes-192-cbc-zeros", "aes-192-cfb", "aes-192-ctr", "aes-192-ofb"}
var algos256 []string = []string{"aes-256-ecb-pkcs5", "aes-256-cbc-pkcs5", "aes-256-cbc-iso10126", "aes-256-cbc-ansix923", "aes-256-cbc-zeros", "aes-256-cfb", "aes-256-ctr", "aes-256-ofb"}

var fixedIV []byte = make([]byte, 16)

var padding string = "pkcs5"

// var plain []byte = []byte(`BEGIN---真正的道德体系建立在理智上的精确和被唤醒的道德情感相平衡的基础上。意义是纯粹而专注于自身的感觉，是人们内心生活的甜味剂。---END`)
var plain []byte = []byte(`BEGIN---1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ---END`)

func B64S(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func HexS(b []byte) string {
	return hex.EncodeToString(b)
}

func checkError(err error, t *testing.T) {
	if err != nil {
		t.Fatal(err)
	}
}

func Test000(t *testing.T) {
	block, _ := aes.NewCipher(key256)
	ent, err := ecbEnc(block, key256, plain, padding)
	checkError(err, t)
	log.Println("ecb:", hex.EncodeToString(ent))
	plt, err := ecbDec(block, key256, ent, padding)
	checkError(err, t)
	log.Println("ecb", string(plt))
}

func Test001(t *testing.T) {
	block, _ := aes.NewCipher(key256)
	ent, err := cbcEnc(block, key256, fixedIV, plain, padding)
	checkError(err, t)
	log.Println("cbc:", hex.EncodeToString(ent))
	plt, err := cbcDec(block, key256, fixedIV, ent, padding)
	checkError(err, t)
	log.Println("cbc", string(plt))
}

func Test002(t *testing.T) {
	block, _ := aes.NewCipher(key256)
	ent, err := cfbEnc(block, key256, fixedIV, plain, padding)
	checkError(err, t)
	log.Println("cfb:", hex.EncodeToString(ent))
	plt, err := cfbDec(block, key256, fixedIV, ent, padding)
	checkError(err, t)
	log.Println("cfb", string(plt))
}

func Test003(t *testing.T) {
	block, _ := aes.NewCipher(key256)
	ent, err := ofbEnc(block, key256, fixedIV, plain, padding)
	checkError(err, t)
	log.Println("ofb:", hex.EncodeToString(ent))
	plt, err := ofbDec(block, key256, fixedIV, ent, padding)
	checkError(err, t)
	log.Println("ofb", string(plt))
}

func Test004(t *testing.T) {
	block, _ := aes.NewCipher(key256)
	ent, err := ctrEnc(block, key256, fixedIV, plain)
	checkError(err, t)
	log.Println("ctr:", hex.EncodeToString(ent))
	plt, err := ctrDec(block, key256, fixedIV, ent)
	checkError(err, t)
	log.Println("ctr", string(plt))
}

func TestAES128(t *testing.T) {
	t.Logf("key128: %s", key128)
	key := key128

	for _, a := range algos128 {
		doTest(a, key, t)
	}
}

func TestAES192(t *testing.T) {
	t.Logf("key192: %s", key192)
	key := key192

	algos := algos192

	for _, a := range algos {
		doTest(a, key, t)
	}
}

func TestAES256(t *testing.T) {
	t.Logf("key256: %s", key256)
	key := key256

	algos := algos256

	for _, a := range algos {
		doTest(a, key, t)
	}
}

func doTest(algo string, key []byte, t *testing.T) {
	var ent, dnt, div []byte
	var err error
	var aes AES

	aes = NewAES(algo)
	ent, err = aes.EncrypterFixedIV(key, fixedIV, plain)

	if showDebug {
		fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
		fmt.Println(algo)
		fmt.Println("Key:", HexS(key))
		fmt.Println("FixedIV:", HexS(fixedIV))
		fmt.Println("CipherText:", HexS(ent))
		fmt.Println("CipherText:", B64S(ent))
		fmt.Println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
	}

	checkError(err, t)
	dnt, err = aes.DecrypterFixedIV(key, fixedIV, ent)
	checkError(err, t)
	if !bytes.Equal(dnt, plain) {
		t.Fatalf("FixedIV %s decrypto don't match", algo)
	}

	ent, div, err = aes.Encrypter(key, plain)
	checkError(err, t)
	if showDebug {
		fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
		fmt.Println(algo)
		fmt.Println("Key:", HexS(key))
		fmt.Println("IV:", HexS(div))
		fmt.Println("CipherText:", HexS(ent))
		fmt.Println("CipherText:", B64S(ent))
		fmt.Println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
	}
	dnt, err = aes.DecrypterFixedIV(key, div, ent)
	if !bytes.Equal(dnt, plain) {
		t.Fatalf("DynamoIV %s decrypto don't match", algo)
	}

	ent, err = aes.EncrypterMixIV(key, plain)
	checkError(err, t)
	if showDebug {
		fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
		fmt.Println(algo)
		fmt.Println("Key:", HexS(key))
		fmt.Println("IV:", HexS(ent[:16]))
		fmt.Println("CipherText:", HexS(ent))
		fmt.Println("CipherText:", B64S(ent))
		fmt.Println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
	}
	dnt, err = aes.DecrypterMixIV(key, ent)
	checkError(err, t)
	if !bytes.Equal(dnt, plain) {
		t.Fatalf("DynamoMixIV %s decrypto don't match", algo)
	}
}
