package mpkg

import (
	"crypto"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	wcrypto "github.com/weidewang/crypto"
)

// Response 业务封包响应报文
type Response struct {
	RespCode  int       `json:"resp_code,omitempty"`
	Remark    string    `json:"remark,omitempty"`
	Errors    []string  `json:"errors,omitempty"`
	Body      string    `json:"body,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	Random    string    `json:"random,omitempty"`
	Sign      string    `json:"sign,omitempty"` // * 不参与签名
	Encrypt   bool      `json:"encrypt"`
	Symkey    string    `json:"symkey,omitempty"`
	KeyPair   *KeyPair  `json:"-"`
}

type ResponseOutput struct {
	RespCode  int
	Remark    string
	Errors    []string
	Body      string
	Timestamp time.Time
}

func (re *Response) sortedParams() string {
	var raws []string
	MakeRaws(&raws, "resp_code", re.RespCode)
	MakeRaws(&raws, "remark", re.Remark)
	if len(re.Errors) > 0 {
		MakeRaws(&raws, "errors", fmt.Sprintf("[%s]", strings.Join(re.Errors, ",")))
	}
	MakeRaws(&raws, "body", re.Body)
	MakeRaws(&raws, "timestamp", re.Timestamp.Format(time.RFC3339))
	MakeRaws(&raws, "random", re.Random)
	MakeRaws(&raws, "encrypt", re.Encrypt)
	MakeRaws(&raws, "symkey", re.Symkey)
	sort.Strings(raws)

	return strings.Join(raws, "&")
}

func (re *Response) Verify() error {
	signByte, err := base64.StdEncoding.DecodeString(re.Sign)
	if err != nil {
		return err
	}
	return wcrypto.PublicKeyVerify(signByte, []byte(re.sortedParams()), crypto.SHA1, re.KeyPair.PublicKey)
}

//  处理body
func (re *Response) processBody() error {
	if !re.Encrypt {
		return nil
	}

	var symKey []byte
	if len(re.Symkey) == 0 {
		symKey = MakeRandByte(aes.BlockSize)
	} else {
		symKey = []byte(re.Symkey)
	}

	enSymKey, err := wcrypto.PublicKeyEncrypt(symKey, re.KeyPair.PublicKey)
	if err != nil {
		return err
	}
	re.Symkey = base64.StdEncoding.EncodeToString(enSymKey)

	eb, err := wcrypto.NewAES(AESAlgorithm).EncrypterMixIV(symKey, []byte(re.Body))
	if err != nil {
		return err
	}
	re.Body = base64.StdEncoding.EncodeToString(eb)
	return nil
}
