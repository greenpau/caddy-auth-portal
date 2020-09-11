// Copyright 2020 Paul Greenberg (greenpau@outlook.com)

package portal

import (
	"github.com/caddyserver/caddy/v2/caddytest"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLocalConfig(t *testing.T) {
	scheme := "https"
	host := "127.0.0.1"
	// port := "3080"
	securePort := "3443"
	authPath := "auth"
	hostPort := host + ":" + securePort
	baseURL := scheme + "://" + hostPort

	tester := caddytest.NewTester(t)
	configFile := "assets/conf/local/config.json"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "json")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")
	req, _ := http.NewRequest(
		"POST",
		baseURL+"/"+authPath,
		strings.NewReader("username=webadmin&password=password123"),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := tester.AssertResponseCode(req, 200)
	t.Logf("%v", resp)
	time.Sleep(1 * time.Second)
}

func TestLdapConfig(t *testing.T) {
	scheme := "https"
	host := "127.0.0.1"
	// port := "3080"
	securePort := "3443"
	authPath := "auth"
	hostPort := host + ":" + securePort
	baseURL := scheme + "://" + hostPort
	tester := caddytest.NewTester(t)
	configFile := "assets/conf/ldap/config.json"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "json")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")
	req, _ := http.NewRequest(
		"POST",
		baseURL+"/"+authPath,
		strings.NewReader("username=webadmin&password=password123&realm=local"),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := tester.AssertResponseCode(req, 200)
	t.Logf("%v", resp)
	time.Sleep(1 * time.Second)
}
