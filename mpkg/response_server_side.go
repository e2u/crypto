package mpkg

import (
	"encoding/hex"
	"encoding/json"
	"time"
	// wcrypto "github.com/weidewang/crypto"
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
	return json.Marshal(re)
}
