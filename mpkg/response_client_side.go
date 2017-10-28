package mpkg

import (
	"encoding/base64"
	"encoding/json"

	wcrypto "github.com/weidewang/crypto"
)

// client side parse server response
func ParseResponse(body []byte, keyPair *KeyPair) (*ResponseOutput, error) {
	var resp Response
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	vo := &ResponseOutput{
		Remark:    resp.Remark,
		RespCode:  resp.RespCode,
		Errors:    resp.Errors,
		Timestamp: resp.Timestamp,
	}

	if resp.RespCode != RespCodeSuccess {
		return vo, nil
	}

	resp.KeyPair = keyPair
	if err := resp.Verify(); err != nil {
		return nil, err
	}

	if !resp.Encrypt {
		vo.Body = resp.Body
		return vo, nil
	}

	bodyByte, err := base64.StdEncoding.DecodeString(resp.Body)
	if err != nil {
		return nil, err
	}

	symkeyByte, err := base64.StdEncoding.DecodeString(resp.Symkey)
	if err != nil {
		return nil, err
	}

	plainSymkey, err := wcrypto.PrivateKeyDecrypt(symkeyByte, resp.KeyPair.PrivateKey)
	if err != nil {
		return nil, err
	}

	plainBody, err := wcrypto.NewAES(AESAlgorithm).DecrypterMixIV(plainSymkey, bodyByte)
	if err != nil {
		return nil, err
	}
	vo.Body = string(plainBody)

	return vo, nil
}
