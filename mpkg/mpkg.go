package mpkg

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	AESAlgorithm      = "aes-128-cbc-pkcs5"
	RespCodeSuccess   = 1000
	RespRemarkSuccess = "success"
)

func MakeRaws(raws *[]string, k string, v interface{}) {
	if len(fmt.Sprintf("%v", v)) == 0 {
		return
	}
	*raws = append(*raws, fmt.Sprintf("%s=%v", k, v))
}

func MakeRandByte(l int) []byte {
	b := make([]byte, l)
	rand.Read(b)
	return b
}

type RequestInput struct {
	URL     string // 请求 URL
	Method  string // 请求方法 [GET|POST]
	Request *Request
}

func HttpDo(input *RequestInput) (*ResponseOutput, error) {
	values, err := input.Request.BuildValues()
	if err != nil {
		return nil, err
	}

	httpResp, err := func() (*http.Response, error) {
		switch input.Method {
		case http.MethodGet:
			return http.Get(fmt.Sprintf("%s?%s", input.URL, values.Encode()))
		case http.MethodPost:
			return http.PostForm(input.URL, values)
		default:
			return nil, http.ErrNotSupported
		}
	}()
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	b, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	return ParseResponse(b, input.Request.KeyPair)
}
