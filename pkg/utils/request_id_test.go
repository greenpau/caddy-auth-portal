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
