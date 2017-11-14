package mpkg

import (
	"crypto"
	"encoding/base64"
	"sort"
	"strings"
	"time"

	wcrypto "github.com/weidewang/crypto"
)

// Request 业务封包请求报文
type Request struct {
	Acq       string    `json:"acq,omitempty"`       // 请求流水号
	Caller    string    `json:"caller,omitempty"`    // 请求方ID
	Body      string    `json:"body,omitempty"`      // 请求正文
	Timestamp time.Time `json:"timestamp,omitempty"` // 请求时间
	TermIP    string    `json:"termip,omitempty"`    // 请求 IP
	Sign      string    `json:"sign,omitempty"`      // 报文签名
	Encrypt   bool      `json:"encrypt"`             // 报文是否加密
	Symkey    string    `json:"symkey,omitempty"`    // 报文加密密钥
	KeyPair   *KeyPair  `json:"-"`                   // 签名,验签,加密 密钥对
}

type RequestOutput struct {
	Acq       string
	Caller    string
	Body      string
	Timestamp time.Time
	TermIP    string
}

func NewRequest() *Request {
	return &Request{}
}

func (r *Request) sortedParams() string {
	var raws []string
	MakeRaws(&raws, "acq", r.Acq)
	MakeRaws(&raws, "caller", r.Caller)
	MakeRaws(&raws, "body", r.Body)
	MakeRaws(&raws, "timestamp", r.Timestamp.Format(time.RFC3339))
	MakeRaws(&raws, "termip", r.TermIP)
	MakeRaws(&raws, "encrypt", r.Encrypt)
	MakeRaws(&raws, "symkey", r.Symkey)
	sort.Strings(raws)
	return strings.Join(raws, "&")
}

func (r *Request) Verify() error {
	signByte, err := base64.StdEncoding.DecodeString(r.Sign)
	if err != nil {
		return err
	}
	return wcrypto.PublicKeyVerify(signByte, []byte(r.sortedParams()), crypto.SHA1, r.KeyPair.PublicKey)
}
