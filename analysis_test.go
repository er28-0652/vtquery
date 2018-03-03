package vtquery

import (
	"testing"
)

func TestShowReportHash(t *testing.T) {
	tests := []string{
		"909349d9beeaf08a155bdfc8aadf73d093e545b7",
		"61b5ac4b9440f41e2a7771445cf2f5d23cbdc8d7",
	}
	vt, err := NewDefaultClient()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		result, err := vt.HashQuery(test)
		if err != nil {
			t.Fatal(err)
		}
		result.ShowReport()
	}
}

func TestShowReportURL(t *testing.T) {
	tests := []string{
		// TAKE CARE! this is malicious
		"http://jpcerts.jpcertinfo.com/",
		// this is normal
		"https://www.google.com",
	}
	vt, err := NewDefaultClient()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		result, err := vt.URLQuery(test)
		if err != nil {
			t.Fatal(err)
		}
		result.ShowReport()
	}
}
