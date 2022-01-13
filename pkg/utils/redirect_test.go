package utils

import (
	"github.com/greenpau/caddy-auth-portal/internal/tests"
	"testing"
)

func TestStripQueryParam(t *testing.T) {

	t.Run("removes a specific query param from a URL", func(t *testing.T) {
		originalUrl := "https://foo.bar/myPage?param1=value&param2=otherValue"
		alteredUrl := StripQueryParam(originalUrl, "param2")
		tests.EvalObjectsWithLog(t, "stripped url", "https://foo.bar/myPage?param1=value", alteredUrl, []string{})
	})

	t.Run("returns original URL if URL cannot be parsed", func(t *testing.T) {
		originalUrl := "glibberish"
		alteredUrl := StripQueryParam(originalUrl, "myParam")
		tests.EvalObjectsWithLog(t, "stripped url", originalUrl, alteredUrl, []string{})
	})

	t.Run("returns original URL if param does not exist in URL", func(t *testing.T) {
		originalUrl := "https://foo.bar/myPage?param1=value"
		alteredUrl := StripQueryParam(originalUrl, "myParam")
		tests.EvalObjectsWithLog(t, "stripped url", originalUrl, alteredUrl, []string{})
	})

}
