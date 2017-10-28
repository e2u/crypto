package mpkg

import (
	"fmt"
	"net/http"
	"testing"

	wcrypto "github.com/weidewang/crypto"
)

var (
	privateKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsu7DGwYtyk45uRSFmyIwHuBjB3tPJOD16YhhuSuO6v1aRV7W
0NGxdbVX+zh49VG5WZ/hNd1U/RRW6GviDvGNv2UztwzxrX0g3qRQ96ZJMqkL6cWZ
qZvthV9l7yO65Bfc5LHVim+PGc/i/XXCQfLzt2JMuAtkkV/oWARUGRRbys/Sd0D5
Yf9fVeHVAvw25SzKjH0hkaYBf/CCLmTsaJtPP9kz9eF7X1klfZggMhrMVjf8Oec/
4YDNuaajYxXtzfGYf7qi17HnQ95Zun7nDVGK6nKAntFWG+0AHHMZh14Qs00o++SV
GHjgfe6rbK5hHj0+OJVoyzEwx/o+scGn2mZ7qwIDAQABAoIBAH5LGfjMDqvZNNLW
kkriAZb5h8wzE7SS999CfL9G6FQiSIHoI7U2HIxZV+UggfedHDcPKtVrCF6s6X6Z
DvC/O+5YjvznrPln9ThQQDnb65RPTvJMn13gifB2WitFS9dMpIPipTdV8Gommi+N
23PS+IR6ZG4O1IfrasIdJAKjpPprL2Se67vwKPrgNLEjK5womv6+xw4yJW+5acRv
6UUms0wWcvV60Qxf23tJ4ngQUDGRWHCRFeyI+GghgnJsecJhiJlYzEH0rpkPACNU
WsA4D6WlKgvzfK1GRkyr6DqaZBarbNbSl6+lA9bILijyhCEAZlLxy7FGwt734hrv
R+D7ewkCgYEA7jTen7p55SzMEgSKR5Sb6hy7a0JDB7fqVxQFOqKZZG4r8cysg3zV
Nh73Fpfz0YHd5GKKs4bgP6dzUyurMe33dbs10Q4Aqi7mFsS087PWZtAfm5v6c/yz
QVKxoXGzk1Rkhu8qe6nN54WinjiokMVSGMfPMIqalhOIcvNpUQOgpU0CgYEAwExr
8dks+ouAGZ7RleJZZP9lJYcJ1M6zBLOMX9q9N7ENsuf0CA4Ti5ogUnj4RkHRPbDY
bkhhlJyw8E62Ej5zkzP+dcJnbLNQU+eAixBHp/yceB+GtyvuvcUk/5mjkWpmjr6l
jZ+hpm1PAdib5eaLN+2/x6JtN9BiDOZbHOj2SNcCgYByn55A3kqprNTGFskziJ8+
GHVXN5tpq2ZoYInjnTqSyTD8ObEJ1JgEYwIjLRt2RTexHnn/yXc/KiSkcO8AJ7Jc
RKmw3zwSqF6vthgc7PzOnHeZOYVbKs5XMKOpPD1dN87n305iE2OxdOy7ligHAexv
YDai9Q9OCDgwmFClW0mCQQKBgGI/qXcriruHwq9UYai+uQXNJxSBZhiAcx6XzcS7
saleoK0jrZ7f8kSFPrZkcBUVU569WBcgjBqt5AkjbgrsNYikLAJmjQkQpJ35zcc/
Th0aB6eoE+BKZfQ3YavmB5goULXl2hf9002A07kRvrU7kS3GHxIUftDhevc0SqD+
tbaJAoGBAMda6yMFkiQdnRQQ555oTCuSSLLbWIyo3Nmr/vieA7urbbSf1uT5iPPT
aIamrUsKLqabTjTtx+wgOaGdQLWizqMIG9OVpyRjaCd0iIB4VfIpXojvbdYZteI8
JR6rJrlndt8iJ+iMy35KAZZx06oRc85uCR/vsTRVGsdK33nVDtS4
-----END RSA PRIVATE KEY-----
`

	publicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsu7DGwYtyk45uRSFmyIw
HuBjB3tPJOD16YhhuSuO6v1aRV7W0NGxdbVX+zh49VG5WZ/hNd1U/RRW6GviDvGN
v2UztwzxrX0g3qRQ96ZJMqkL6cWZqZvthV9l7yO65Bfc5LHVim+PGc/i/XXCQfLz
t2JMuAtkkV/oWARUGRRbys/Sd0D5Yf9fVeHVAvw25SzKjH0hkaYBf/CCLmTsaJtP
P9kz9eF7X1klfZggMhrMVjf8Oec/4YDNuaajYxXtzfGYf7qi17HnQ95Zun7nDVGK
6nKAntFWG+0AHHMZh14Qs00o++SVGHjgfe6rbK5hHj0+OJVoyzEwx/o+scGn2mZ7
qwIDAQAB
-----END PUBLIC KEY-----`
)

func TestHttpDo(t *testing.T) {
	privateKey, _ := wcrypto.ParsePrivateKey([]byte(privateKeyPem))
	publicKey, _ := wcrypto.ParsePublicKey([]byte(publicKeyPem))

	keyPair := &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
	input := &RequestInput{
		Method: http.MethodPost,
		URL:    "http://127.0.0.1:9000/v1",
		Request: &Request{
			Body:    "YT1oZWxsbwo=",
			Caller:  "gateway",
			Encrypt: true,
			KeyPair: keyPair,
		},
	}
	resp, err := HttpDo(input)
	fmt.Println(resp, err)
}
