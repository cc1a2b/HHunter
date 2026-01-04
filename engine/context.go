package engine

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"time"
)

type RequestContext struct {
	URL         string
	Method      string
	Headers     map[string]string
	Body        []byte
	ProxyURL    string
	Timeout     time.Duration
	FollowRedir bool
}

type ResponseContext struct {
	StatusCode    int
	Headers       map[string][]string
	Body          []byte
	BodyHash      string
	ContentLength int64
	TimingMS      int64
	JSONKeys      []string
	Error         error
}

type Mutation struct {
	Header   string
	Value    string
	Category string
	Impact   string
}

type Finding struct {
	Header      string            `json:"header"`
	Payload     string            `json:"payload"`
	Impact      string            `json:"impact"`
	Confidence  string            `json:"confidence"`
	Evidence    map[string]string `json:"evidence"`
	Category    string            `json:"category"`
	Severity    string            `json:"severity"`
	Request     string            `json:"request,omitempty"`
	Response    string            `json:"response,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

func NewRequestContext(url, method string) *RequestContext {
	return &RequestContext{
		URL:         url,
		Method:      method,
		Headers:     make(map[string]string),
		Timeout:     30 * time.Second,
		FollowRedir: false,
	}
}

func (rc *RequestContext) Clone() *RequestContext {
	clone := &RequestContext{
		URL:         rc.URL,
		Method:      rc.Method,
		Headers:     make(map[string]string),
		Body:        rc.Body,
		ProxyURL:    rc.ProxyURL,
		Timeout:     rc.Timeout,
		FollowRedir: rc.FollowRedir,
	}
	for k, v := range rc.Headers {
		clone.Headers[k] = v
	}
	return clone
}

func (rc *RequestContext) AddHeader(key, value string) {
	rc.Headers[key] = value
}

func (rc *RequestContext) Execute(client *http.Client) (*ResponseContext, error) {
	start := time.Now()

	req, err := http.NewRequest(rc.Method, rc.URL, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range rc.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		return &ResponseContext{
			Error:    err,
			TimingMS: elapsed,
		}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ResponseContext{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			TimingMS:   elapsed,
			Error:      err,
		}, err
	}

	hash := sha256.Sum256(body)

	return &ResponseContext{
		StatusCode:    resp.StatusCode,
		Headers:       resp.Header,
		Body:          body,
		BodyHash:      fmt.Sprintf("%x", hash),
		ContentLength: resp.ContentLength,
		TimingMS:      elapsed,
	}, nil
}
