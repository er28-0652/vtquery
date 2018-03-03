package vtquery

import (
	"fmt"
	"testing"
)

func TestHashQuery(t *testing.T) {
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
		if result.Attributes.Sha1 != test {
			t.Errorf("got=%#v\nwant=%#v", result.Attributes.Sha1, test)
		}
	}
}

func TestHashQuery_fail(t *testing.T) {
	vt, err := NewDefaultClient()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("invalid query case", func(t *testing.T) {
		_, err := vt.HashQuery("hogehoge")
		expect := "invalid hash query"
		if err.Error() != expect {
			t.Errorf("got=%#v\nwant=%#v", err, expect)
		}
	})

	t.Run("not found case", func(t *testing.T) {
		q := "61b5ac4b9440f41e2a7771445cf2f5d23cbdc8d9"
		_, err := vt.HashQuery(q)
		expect := fmt.Sprintf("\"%s\" is not found in VT", q)
		if err.Error() != expect {
			t.Errorf("got=%#v\nwant=%#v", err, expect)
		}
	})
}
