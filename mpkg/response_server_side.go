package mpkg

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	wcrypto "github.com/weidewang/crypto"
)

func (re *Response) Build() ([]byte, error) {

	if re.Timestamp.IsZero() {
		re.Timestamp = time.Now()
	}

	if len(re.Random) == 0 {
		re.Random = hex.EncodeToString(MakeRandByte(16))
	}
    

	if err := re.processBody(); err != nil {
		return nil, err
	}

	sign, err := wcrypto.PrivateKeySign([]byte(re.sortedParams()), crypto.SHA1, re.KeyPair.PrivateKey)
	if err != nil {
		return nil, err
	}
	re.Sign = base64.StdEncoding.EncodeToString(sign)
    

	return json.Marshal(re)
}
