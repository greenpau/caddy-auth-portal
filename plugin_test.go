// Copyright 2020 Paul Greenberg (greenpau@outlook.com)

package jwt

import (
	"github.com/caddyserver/caddy/v2/caddytest"
	"testing"
	"time"
)

func TestPlugin(t *testing.T) {
	// Define URL
	baseURL := "https://127.0.0.1:3443"

	// Load configuration file
	configFile := "assets/conf/Caddyfile.json"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)

	caddytest.InitServer(t, rawConfig, "json")

	caddytest.AssertGetResponse(t, baseURL+"/version", 200, "1.0.0")
	caddytest.AssertGetResponse(t, baseURL+"/health", 401, "")

	time.Sleep(1 * time.Millisecond)
	// Uncomment the below line to perform manual testing
	// time.Sleep(6000 * time.Second)
}
