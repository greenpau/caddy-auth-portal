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
	"fmt"
	"net/http"
	"testing"
)

func TestGetSourceAddress(t *testing.T) {
	testFailed := 0
	tests := []struct {
		addr   string
		hname  string
		hvalue string
		result string
	}{
		{
			addr:   "192.168.99.40:23467",
			result: "192.168.99.40",
		},
		{
			addr:   "192.168.99.40:23467",
			hname:  "x-real-ip",
			hvalue: "10.10.10.10",
			result: "10.10.10.10",
		},
		{
			addr:   "192.168.99.40:23467",
			hname:  "X-real-IP",
			hvalue: "10.10.10.10",
			result: "10.10.10.10",
		},
		{
			addr:   "192.168.99.40:23467",
			hname:  "X-Forwarded-For",
			hvalue: "100.100.2.2, 192.168.0.10",
			result: "100.100.2.2",
		},
		{
			addr:   "192.168.99.40:23467",
			hname:  "X-Forwarded-For",
			hvalue: "192.168.0.10",
			result: "192.168.0.10",
		},
	}
	for i, test := range tests {
		r, err := http.NewRequest("GET", "127.0.0.1", nil)
		if err != nil {
			t.Fatalf("Failed creating HTTP request")
		}
		r.RemoteAddr = test.addr
		testDescr := fmt.Sprintf("Test %d, addr: %s, result: %s", i, test.addr, test.result)
		if test.hname != "" {
			testDescr += fmt.Sprintf(", header: %s, value, %s", test.hname, test.hvalue)
			r.Header.Add(test.hname, test.hvalue)
		}

		addr := GetSourceAddress(r)
		if addr != test.result {
			t.Logf("FAIL: %s, received: %s", testDescr, addr)
			testFailed++
			continue
		}
		t.Logf("PASS: %s", testDescr)
	}

	if testFailed > 0 {
		t.Fatalf("Failed %d tests", testFailed)
	}
}
