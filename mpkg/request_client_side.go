package mpkg

import (
	"crypto"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"time"

	wcrypto "github.com/weidewang/crypto"
)

func (r *Request) BuildValues() (url.Values, error) {
	values := url.Values{}

	if len(r.Acq) == 0 {
		r.Acq = fmt.Sprintf("%d-%s", time.Now().UnixNano(), hex.EncodeToString(MakeRandByte(4)))
	}
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now()
	}
	if len(r.TermIP) == 0 {
		r.TermIP = "noset"
	}
	if err := r.processBody(); err != nil {
		return values, err
	}
	if err := r.signature(); err != nil {
		return values, err
	}

	values.Set("acq", r.Acq)
	values.Set("body", r.Body)
	values.Set("caller", r.Caller)
	values.Set("symkey", r.Symkey)
	values.Set("timestamp", r.Timestamp.Format(time.RFC3339))
	values.Set("termip", r.TermIP)
	values.Set("encrypt", strconv.FormatBool(r.Encrypt))
	values.Set("sign", r.Sign)

	return values, nil
}

//  处理body
func (r *Request) processBody() error {
	if !r.Encrypt {
		return nil
	}

	var symKey []byte
	if len(r.Symkey) == 0 {
		symKey = MakeRandByte(aes.BlockSize)
	} else {
		symKey = []byte(r.Symkey)
	}
	enSymKey, err := wcrypto.PublicKeyEncrypt(symKey, r.KeyPair.PublicKey)
	if err != nil {
		return err
	}
	r.Symkey = base64.StdEncoding.EncodeToString(enSymKey)

	eb, err := wcrypto.NewAES(AESAlgorithm).EncrypterMixIV(symKey, []byte(r.Body))
	if err != nil {
		return err
	}
	r.Body = base64.StdEncoding.EncodeToString(eb)
	return nil
}

func (r *Request) signature() error {
	fmt.Println(r.sortedParams())
	sign, err := wcrypto.PrivateKeySign([]byte(r.sortedParams()), crypto.SHA1, r.KeyPair.PrivateKey)
	if err != nil {
		return err
	}
	r.Sign = base64.StdEncoding.EncodeToString(sign)
	return nil
}
