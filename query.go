package vtquery

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

func decodeBody(resp *http.Response, out interface{}) error {
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	return decoder.Decode(out)
}

func (c *Client) search(query string, result interface{}) error {
	// Create instaßnce of RequestOptions with given query keyword
	ro := &RequestOptions{
		Params: map[string]string{
			"query":                  query,
			"relationships[url]":     "network_location,last_serving_ip_address",
			"relationships[comment]": "author,item",
		},
	}

	req, err := c.newRequest("GET", "/ui/search", ro)
	if err != nil {
		return errors.Wrap(err, "fail to create new request")
	}

	// Send HTTP request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "fail to send request")
	}

	// Check status code
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s; url=%s", res.Status, req.URL.String())
	}

	// Decode the response body as given type of JSON
	return decodeBody(res, result)
}

// HashQuery query the given hash to VirusTotal and returns the result as JSON
func (c *Client) HashQuery(query string) (result *HashQueryResult, err error) {
	err = c.search(query, result)
	return result, err
}

// URLQuery query the given URL/IP to VirusTotal and returns the result as JSON
func (c *Client) URLQuery(query string) (result *URLQueryResult, err error) {
	err = c.search(query, result)
	return result, err
}
