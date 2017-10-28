package mpkg

import "crypto/rsa"

type KeyPair struct {
	// keyPair 在 Request 中时:
	// PrivateKey 是发送方的私钥, PublicKey 是接收方的公钥
	// 私钥用于发送数据的签名,公钥用于对成加密密钥的加密,接收方收到加密报文后,用其私钥获取对称加密密钥,并用密钥(对称加密)解密密文
	// KeyPair 在 Response 中时:
	// PrivateKey 是接收方的私钥, PublicKey 是发送方的公钥
	// 用公钥对收到的数据进行签名验证,如接收到的报文是加密的密文,则用私钥解密获取对称加密的密钥,并用密钥(对称加密)解密密文
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}
