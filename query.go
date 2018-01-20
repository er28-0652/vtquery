package vtquery

import (
	"encoding/json"
	"fmt"
	"net/http"
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
		return err
	}

	// Send HTTP request
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	// Check status code
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("query: %s", res.Status)
	}

	// Decode the response body as given type of JSON
	return decodeBody(res, result)
}

// HashQuery query the given hash to VirusTotal and returns the result as JSON
func (c *Client) HashQuery(query string) (*HashQueryResult, error) {
	var result HashQueryResult
	if err := c.search(query, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// URLQuery query the given URL/IP to VirusTotal and returns the result as JSON
func (c *Client) URLQuery(query string) (*URLQueryResult, error) {
	var result URLQueryResult
	if err := c.search(query, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
