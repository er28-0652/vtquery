package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// AnalysisResult represents generic analysis result for both hash and url.
type AnalysisResult struct {
	Category      string `json:"category"`
	EngineName    string `json:"engine_name"`
	EngineUpdate  string `json:"engine_update"`
	EngineVersion string `json:"engine_version"`
	Method        string `json:"method"`
	Result        string `json:"result"`
}

// HashQueryResult is File Hash analysis result as JSON.
type HashQueryResult struct {
	Data []struct {
		Attributes struct {
			Exiftool struct {
				FileType          string `json:"FileType"`
				FileTypeExtension string `json:"FileTypeExtension"`
				MIMEType          string `json:"MIMEType"`
			} `json:"exiftool"`
			FirstSubmissionDate int                       `json:"first_submission_date"`
			LastAnalysisDate    int                       `json:"last_analysis_date"`
			LastAnalysisResults map[string]AnalysisResult `json:"last_analysis_results"`
			LastAnalysisStats   struct {
				Failure         int `json:"failure"`
				Harmless        int `json:"harmless"`
				Malicious       int `json:"malicious"`
				Suspicious      int `json:"suspicious"`
				Timeout         int `json:"timeout"`
				TypeUnsupported int `json:"type-unsupported"`
				Undetected      int `json:"undetected"`
			} `json:"last_analysis_stats"`
			LastSubmissionDate int      `json:"last_submission_date"`
			Magic              string   `json:"magic"`
			Md5                string   `json:"md5"`
			Names              []string `json:"names"`
			Reputation         int      `json:"reputation"`
			RtfInfo            struct {
				DocumentProperties struct {
					CustomXMLDataProperties int      `json:"custom_xml_data_properties"`
					DefaultAnsiCodepage     string   `json:"default_ansi_codepage"`
					DefaultCharacterSet     string   `json:"default_character_set"`
					DefaultLanguages        []string `json:"default_languages"`
					DosStubs                int      `json:"dos_stubs"`
					EmbeddedDrawings        int      `json:"embedded_drawings"`
					EmbeddedPictures        int      `json:"embedded_pictures"`
					Generator               string   `json:"generator"`
					LongestHexString        int      `json:"longest_hex_string"`
					NonASCIICharacters      int      `json:"non_ascii_characters"`
					Objects                 []struct {
						Class string `json:"class"`
						Type  string `json:"type"`
					} `json:"objects"`
					ReadOnlyProtection bool   `json:"read_only_protection"`
					RtfHeader          string `json:"rtf_header"`
					UserProtection     bool   `json:"user_protection"`
				} `json:"document_properties"`
			} `json:"rtf_info"`
			Sha1           string   `json:"sha1"`
			Sha256         string   `json:"sha256"`
			Size           int      `json:"size"`
			Ssdeep         string   `json:"ssdeep"`
			Tags           []string `json:"tags"`
			TimesSubmitted int      `json:"times_submitted"`
			TotalVotes     struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
			Trid []struct {
				FileType    string  `json:"file_type"`
				Probability float64 `json:"probability"`
			} `json:"trid"`
			TypeDescription string `json:"type_description"`
			TypeTag         string `json:"type_tag"`
			Vhash           string `json:"vhash"`
		} `json:"attributes"`
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Type string `json:"type"`
	} `json:"data"`
	Links struct {
		Self string `json:"self"`
	} `json:"links"`
}

// URLQueryResult is URL analysis result as JSON.
type URLQueryResult struct {
	Data []struct {
		Attributes struct {
			Categories struct {
				ForcepointThreatSeeker string `json:"Forcepoint ThreatSeeker"`
			} `json:"categories"`
			FirstSubmissionDate int                       `json:"first_submission_date"`
			LastAnalysisDate    int                       `json:"last_analysis_date"`
			LastAnalysisResults map[string]AnalysisResult `json:"last_analysis_results"`
			LastAnalysisStats   struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Timeout    int `json:"timeout"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			LastFinalURL       string        `json:"last_final_url"`
			LastSubmissionDate int           `json:"last_submission_date"`
			Reputation         int           `json:"reputation"`
			Tags               []interface{} `json:"tags"`
			TimesSubmitted     int           `json:"times_submitted"`
			TotalVotes         struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
			URL string `json:"url"`
		} `json:"attributes"`
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Relationships struct {
			LastServingIPAddress struct {
				Data struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
				Links struct {
					Related string `json:"related"`
					Self    string `json:"self"`
				} `json:"links"`
			} `json:"last_serving_ip_address"`
			NetworkLocation struct {
				Data struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
				Links struct {
					Related string `json:"related"`
					Self    string `json:"self"`
				} `json:"links"`
			} `json:"network_location"`
		} `json:"relationships"`
		Type string `json:"type"`
	} `json:"data"`
	Links struct {
		Self string `json:"self"`
	} `json:"links"`
}

func decodeBody(resp *http.Response, out interface{}) error {
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	return decoder.Decode(out)
}

func (c *Client) search(query string, result interface{}) error {
	// Create instance of RequestOptions with given query keyword
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
	if res.StatusCode != 200 {
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
