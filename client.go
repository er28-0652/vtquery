package vtquery

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/pkg/errors"
)

// Client is basic client structure for VirusTotal API
type Client struct {
	URL           *url.URL
	HTTPClient    *http.Client
	DefaultHeader http.Header
}

// NewClient creates instance of Client with given parameters.
func NewClient(baseURL, userAgent string, insecure bool) (*Client, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, errors.Wrapf(err, "client: fail to parse \"%s\"", baseURL)
	}

	client := &Client{
		URL:           parsedURL,
		HTTPClient:    &http.Client{},
		DefaultHeader: make(http.Header),
	}
	client.DefaultHeader.Set("User-Agent", userAgent)

	// Add flag to ignore insecure HTTPS connection
	if insecure == true {
		tlsConfig := tls.Config{
			InsecureSkipVerify: insecure,
		}

		transport := *http.DefaultTransport.(*http.Transport)
		transport.TLSClientConfig = &tlsConfig

		client.HTTPClient = &http.Client{
			Transport: &transport,
		}
	}
	return client, nil
}

// NewDefaultClient creates instance with default URL and User-Agent
func NewDefaultClient() (*Client, error) {
	baseURL := "https://www.virustotal.com"
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36"

	client, err := NewClient(baseURL, userAgent, false)
	if err != nil {
		return nil, errors.Wrap(err, "client: fail to create new Client")
	}
	return client, nil
}

// RequestOptions is the list of options to pass to the request.
type RequestOptions struct {
	// Params is a map of key-value pairs that will be added to the Request.
	Params map[string]string

	// Body is an io.Reader object that will be streamed or uploaded with the
	// Request. BodyLength is the final size of the Body.
	Body       io.Reader
	BodyLength int64
}

func (c *Client) newRequest(method, spath string, ro *RequestOptions) (*http.Request, error) {
	if method == "" {
		return nil, fmt.Errorf("client: missing method")
	}

	// ensure to have a RequestOptions struct
	if ro == nil {
		ro = new(RequestOptions)
	}

	// Create a new URL with the appended path
	u := *c.URL
	u.Path = path.Join(c.URL.Path, spath)

	// Add parameters
	var params = make(url.Values)
	for k, v := range ro.Params {
		params.Add(k, v)
	}
	u.RawQuery = params.Encode()

	// Create Request object
	req, err := http.NewRequest(method, u.String(), ro.Body)
	if err != nil {
		return nil, errors.Wrap(err, "client: fail to create new Request")
	}

	// Add User-Agent to Header
	req.Header = c.DefaultHeader

	// Add content-length if we have it
	if ro.BodyLength > 0 {
		req.ContentLength = ro.BodyLength
	}

	return req, nil
}
