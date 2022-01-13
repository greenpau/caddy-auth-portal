// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"github.com/greenpau/caddy-auth-portal/internal/tests"
	"testing"
)

func TestStripQueryParam(t *testing.T) {

	t.Run("removes a specific query param from a URL", func(t *testing.T) {
		originalURL := "https://foo.bar/myPage?param1=value&param2=otherValue"
		alteredURL := StripQueryParam(originalURL, "param2")
		tests.EvalObjectsWithLog(t, "stripped url", "https://foo.bar/myPage?param1=value", alteredURL, []string{})
	})

	t.Run("returns original URL if URL cannot be parsed", func(t *testing.T) {
		originalURL := "glibberish"
		alteredURL := StripQueryParam(originalURL, "myParam")
		tests.EvalObjectsWithLog(t, "stripped url", originalURL, alteredURL, []string{})
	})

	t.Run("returns original URL if param does not exist in URL", func(t *testing.T) {
		originalURL := "https://foo.bar/myPage?param1=value"
		alteredURL := StripQueryParam(originalURL, "myParam")
		tests.EvalObjectsWithLog(t, "stripped url", originalURL, alteredURL, []string{})
	})

}
