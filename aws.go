package elastic

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/private/signer/v4"
)

const SERVICE_NAME = "es"

func getRegion(url string) string {
	urlSplitted := strings.Split(url, ".")
	return urlSplitted[len(urlSplitted)-4]
}

func SignAWSESServiceRequest(req *http.Request) error {
	var body []byte
	var err error

	if req.Body != nil {
		body, err = ioutil.ReadAll(req.Body)
		if err != nil {
			return err
		}
	}

	if req.Method == "GET" || req.Method == "HEAD" {
		delete(req.Header, "Content-Length")
	}

	oldPath := req.URL.Path
	if oldPath != "" {
		// Escape the path before signing so that the path in the signature and
		// the path in the request match.
		req.URL.Path = req.URL.EscapedPath()
	}

	awsReq := &request.Request{}
	awsReq.Config.Credentials = defaults.CredChain(defaults.Config(), defaults.Handlers())
	awsReq.Config.Region = aws.String(getRegion(req.URL.Host))
	awsReq.ClientInfo.ServiceName = SERVICE_NAME
	awsReq.HTTPRequest = req
	awsReq.Time = time.Now()
	awsReq.ExpireTime = 0

	if body != nil {
		awsReq.Body = bytes.NewReader(body)
	}

	v4.Sign(awsReq)

	if awsReq.Error != nil {
		return awsReq.Error
	}

	req.URL.Path = oldPath
	if body != nil {
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
	}

	return nil

}
