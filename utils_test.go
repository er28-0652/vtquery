package vtquery

import "testing"

func TestValidation(t *testing.T) {
	t.Run("file case", func(t *testing.T) {
		tests := map[string]bool{
			"caa72db19bcbaaaa3bcf63504cdb098d":                                  true,  // MD5
			"909349d9beeaf08a155bdfc8aadf73d093e545b7":                          true,  // SHA1
			"3192b5beba912e2cc46eb5468516276bb4f6dfaef8105e70a5ac8f2039484575":  true,  //SHA256
			"caa72db19bcbaaaa3bcf63504cdb098":                                   false, // invalid
			"909349d9beeaf08a155bdfc8aadf73d093e545b":                           false, // invalid
			"909349d9beeaf08a155bdfc8aadf73d093e545b7AAAAAAAAAAAAAA":            false, // invalid
			"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ":                                  false, // invalid
			"3192b5beba912e2cc46eb5468516276bb4f6dfaef8105e70a5ac8f203948457":   false,
			"3192b5beba912e2cc46eb5468516276bb4f6dfaef8105e70a5ac8f203948457Z":  false,
			"3192b5beba912e2cc46eb5468516276bb4f6dfaef8105e70a5ac8f203948457ZZ": false,
		}
		for test, expect := range tests {
			if IsValidHash(test) != expect {
				t.Errorf("%s is %t", test, !expect)
			}
		}
	})
	t.Run("url case", func(t *testing.T) {
		tests := map[string]bool{
			"http://google.com":                          true,
			"https://google.com":                         true,
			"https://google.com/this/is/test/path/yayay": true,
			"http://192.168.0.1/":                        true,
			"hxxp://google.com":                          false,
			"http:/google.com":                           false,
		}
		for test, expect := range tests {
			if IsValidURL(test) != expect {
				t.Errorf("%s is %t", test, !expect)
			}
		}
	})
}
