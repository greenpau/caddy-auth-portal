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

	var testcases = []struct {
		name  string
		url   string
		param string
		want  string
	}{
		{
			name:  "removes a specific query param from a URL",
			url:   "https://foo.bar/myPage?param1=value&param2=otherValue",
			param: "param2",
			want:  "https://foo.bar/myPage?param1=value",
		},
		{
			name:  "returns original URL if URL cannot be parsed",
			url:   "glibberish",
			param: "myParam",
			want:  "glibberish",
		},
		{
			name:  "returns original URL if param does not exist in URL",
			url:   "https://foo.bar/myPage?param1=value",
			param: "myParam",
			want:  "https://foo.bar/myPage?param1=value",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			alteredURL := StripQueryParam(tc.url, tc.param)
			tests.EvalObjectsWithLog(t, "stripped url", tc.want, alteredURL, []string{})
		})
	}
}
