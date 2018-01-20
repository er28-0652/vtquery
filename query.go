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

func (c *Client) search(query string, data interface{}) error {
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
	result := &Result{}
	err = decodeBody(res, result)
	if err != nil {
		return errors.Wrap(err, "failt to decode response")
	}

	// if Result::Data is nil slice, it means no data on VT
	if len(result.Data) == 0 {
		return fmt.Errorf("\"%s\" is not found in VT", query)
	}

	// Decode Data
	jsonResult, err := json.Marshal(result.Data)
	if err != nil {
		return errors.Wrap(err, "failt to decode result as json")
	}
	err = json.Unmarshal(jsonResult, data)
	if err != nil {
		return errors.Wrap(err, "fail to decode data")
	}
	return nil
}

// HashQuery query the given hash to VirusTotal and returns the result as JSON
func (c *Client) HashQuery(query string) (*HashQueryResult, error) {
	if !IsValidHash(query) {
		return nil, errors.New("invalid hash query")
	}
	var result []HashQueryResult
	err := c.search(query, &result)
	if err != nil {
		return nil, err
	}
	return &result[0], nil
}

// URLQuery query the given URL/IP to VirusTotal and returns the result as JSON
func (c *Client) URLQuery(query string) (*URLQueryResult, error) {
	if !IsValidURL(query) {
		return nil, errors.New("invalid url query")
	}
	var result []URLQueryResult
	err := c.search(query, &result)
	if err != nil {
		return nil, err
	}
	return &result[0], nil
}
