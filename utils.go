package vtquery

import "regexp"

var (
	// regexp for MD5, SHA1 and SHA256
	hashPtn = regexp.MustCompile(`(^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$)`)

	// regexp for URL pattern
	urlPtn = regexp.MustCompile(`^https?://.*`)
)

// IsValidHash checks if argument is valid MD5, SHA1 or SHA256
func IsValidHash(obj string) bool {
	return hashPtn.MatchString(obj)
}

// IsValidURL checks if argument is valid URL scheme
func IsValidURL(obj string) bool {
	return urlPtn.MatchString(obj)
}
