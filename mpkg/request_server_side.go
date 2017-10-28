package mpkg

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	wcrypto "github.com/weidewang/crypto"
)

// server side parse request
// use KeyPair.PublicKey verify message
func ParseHttpRequest(httpRequest *http.Request, keypair *KeyPair) (*RequestOutput, error) {
	r, err := cloneRequest(httpRequest)
	if err != nil {
		return nil, err
	}

	timestamp, err := time.Parse(time.RFC3339, r.FormValue("timestamp"))
	if err != nil {
		return nil, err
	}

	req := Request{
		Acq:    r.FormValue("acq"),
		Body:   r.FormValue("body"),
		Caller: r.FormValue("caller"),
		Encrypt: func() bool {
			v, err := strconv.ParseBool(r.FormValue("encrypt"))
			if err != nil {
				return false
			}
			return v
		}(),
		KeyPair:   keypair,
		Sign:      r.FormValue("sign"),
		Symkey:    r.FormValue("symkey"),
		TermIP:    r.FormValue("termip"),
		Timestamp: timestamp,
	}

	if err := req.Verify(); err != nil {
		return nil, err
	}

	vo := &RequestOutput{
		Acq:       req.Acq,
		Caller:    req.Caller,
		TermIP:    req.TermIP,
		Timestamp: req.Timestamp,
	}

	if !req.Encrypt {
		vo.Body = req.Body
		return vo, nil
	}

	symkeyBytes, err := base64.StdEncoding.DecodeString(req.Symkey)
	if err != nil {
		return nil, err
	}

	symkey, err := wcrypto.PrivateKeyDecrypt(symkeyBytes, req.KeyPair.PrivateKey)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := base64.StdEncoding.DecodeString(req.Body)
	if err != nil {
		return nil, err
	}

	plainByte, err := wcrypto.NewAES(AESAlgorithm).DecrypterMixIV(symkey, bodyBytes)
	if err != nil {
		return nil, err
	}
	vo.Body = string(plainByte)

	return vo, nil
}

func cloneRequest(r *http.Request) (*http.Request, error) {
	bodyByte, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyByte))
	cpReq := &http.Request{
		Body:             ioutil.NopCloser(bytes.NewBuffer(bodyByte)),
		ContentLength:    r.ContentLength,
		Form:             r.Form,
		Header:           r.Header,
		Host:             r.Host,
		Method:           r.Method,
		MultipartForm:    r.MultipartForm,
		PostForm:         r.PostForm,
		Proto:            r.Proto,
		ProtoMajor:       r.ProtoMajor,
		ProtoMinor:       r.ProtoMinor,
		RemoteAddr:       r.RemoteAddr,
		RequestURI:       r.RequestURI,
		TransferEncoding: r.TransferEncoding,
		URL:              r.URL,
	}
	return cpReq, nil
}
