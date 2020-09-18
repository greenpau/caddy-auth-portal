package utils

import (
	"fmt"
	"strings"
)

const allowedChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/_-.!~"

// ContainsInvalidChars returns error if the provided string contains
// characters outside of the allowed character set.
func ContainsInvalidChars(charset, s string) error {
	for i, c := range s {
		if !strings.Contains(charset, strings.ToLower(string(c))) &&
			!strings.Contains(charset, strings.ToUpper(string(c))) {
			return fmt.Errorf("string %s contains forbidden character %d, pos: %d", s, c, i)
		}
	}
	return nil
}

// ContainsValidCharset returns error if the provided string contains
// characters outside of the provided character set.
func ContainsValidCharset(charset, s string) error {
	for i, c := range s {
		if !strings.Contains(charset, string(c)) {
			return fmt.Errorf("string %s contains forbidden character %d, pos: %d", s, c, i)
		}
	}
	return nil
}
