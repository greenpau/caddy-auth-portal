package portal

import (
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-portal/pkg/core"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestAuthenticateShortLocalCaddyfile(t *testing.T) {
	scheme := "https"
	host := "127.0.0.1"
	securePort := "8443"
	authPath := "auth"
	hostPort := host + ":" + securePort
	baseURL := scheme + "://" + hostPort
	tester := caddytest.NewTester(t)
	configFile := "assets/conf/local/Caddyfile.short"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")

	if core.PortalManager.MemberCount != 1 {
		t.Errorf("expected one AuthPortal, got %d", core.PortalManager.MemberCount)
	}
	p := core.PortalManager.Members[0]

	logger := zap.NewExample()

	reqBackendRealm := "local"
	reqBackendMethod := "POST"

	opts := make(map[string]interface{})
	opts["auth_credentials"] = map[string]string{
		"username": "webadmin",
		"password": "password123",
	}
	expectedRoles := []string{
		"superadmin",
		"anonymous",
		"guest",
	}

	for _, backend := range p.Backends {
		if backend.GetRealm() != reqBackendRealm {
			continue
		}
		//opts["request"] = r
		opts["request_path"] = path.Join(p.AuthURLPath, reqBackendMethod, reqBackendRealm)
		resp, err := backend.Authenticate(opts)
		if err != nil {
			t.Errorf("Authenticate failed: %s", err)
		}
		claims := resp["claims"].(*jwtclaims.UserClaims)
		p.RoleMappers.Logger = logger
		p.RoleMappers.ApplyRoleMapToClaims(claims, backend.GetRealm())
		if len(claims.Roles) != 3 {
			// original code results in superadmin,anonymous,guest
			t.Errorf("Expected %d role (%s) got : %s",
				len(expectedRoles),
				strings.Join(expectedRoles, ","),
				strings.Join(claims.Roles, ","),
			)
		}
	}

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

	// faking it - the init() in portal.go is only going to be called once...
	core.PortalManager = &core.AuthPortalManager{}
}

func TestAuthenticateRolemapperShortLocalCaddyfile(t *testing.T) {
	scheme := "https"
	host := "127.0.0.1"
	securePort := "8443"
	authPath := "auth"
	hostPort := host + ":" + securePort
	baseURL := scheme + "://" + hostPort
	tester := caddytest.NewTester(t)
	configFile := "assets/conf/local/Caddyfile.rolemapper.short"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")

	if core.PortalManager.MemberCount != 1 {
		t.Errorf("expected one AuthPortal, got %d", core.PortalManager.MemberCount)
	}
	p := core.PortalManager.Members[0]

	logger := zap.NewExample()

	reqBackendRealm := "local"
	reqBackendMethod := "POST"

	opts := make(map[string]interface{})
	opts["auth_credentials"] = map[string]string{
		"username": "webadmin",
		"password": "password123",
	}

	expectedRoles := []string{
		"superadmin",
		"anonymous",
		"guest",
		"rolemapping_regex",
		"rolemapping_add",
		"fileadminlocaldomain",
	}

	for _, backend := range p.Backends {
		if backend.GetRealm() != reqBackendRealm {
			continue
		}
		//opts["request"] = r
		opts["request_path"] = path.Join(p.AuthURLPath, reqBackendMethod, reqBackendRealm)
		resp, err := backend.Authenticate(opts)
		if err != nil {
			t.Errorf("Authenticate failed: %s", err)
		}
		claims := resp["claims"].(*jwtclaims.UserClaims)
		p.RoleMappers.Logger = logger
		p.RoleMappers.ApplyRoleMapToClaims(claims, backend.GetRealm())
		if len(claims.Roles) != len(expectedRoles) {
			// original code results in superadmin,anonymous,guest
			t.Errorf("Expected %d role (%s) got : %s",
				len(expectedRoles),
				strings.Join(expectedRoles, ","),
				strings.Join(claims.Roles, ","),
			)
		}
	}

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

	// faking it - the init() in portal.go is only going to be called once...
	core.PortalManager = &core.AuthPortalManager{}
}

// the long version uses the expanded version of the local_backend caddyfile cfg
// and has 2 local_backends to show the different role mappings
func TestAuthenticateRolemapperLocalCaddyfile(t *testing.T) {
	tester := caddytest.NewTester(t)
	configFile := "assets/conf/local/Caddyfile.rolemapper"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")

	if core.PortalManager.MemberCount != 1 {
		t.Errorf("expected one AuthPortal, got %d", core.PortalManager.MemberCount)
	}
	p := core.PortalManager.Members[0]

	logger := zap.NewExample()

	{
		reqBackendRealm := "firstlocal"
		reqBackendMethod := "POST"

		opts := make(map[string]interface{})
		opts["auth_credentials"] = map[string]string{
			"username": "webadmin",
			"password": "password123",
		}

		expectedRoles := []string{
			"superadmin",
			"anonymous",
			"guest",
			"rolemapping_regex",
			"rolemapping_add",
			"fileadminlocaldomain",
		}

		for _, backend := range p.Backends {
			if backend.GetRealm() != reqBackendRealm {
				continue
			}
			//opts["request"] = r
			opts["request_path"] = path.Join(p.AuthURLPath, reqBackendMethod, reqBackendRealm)
			resp, err := backend.Authenticate(opts)
			if err != nil {
				t.Errorf("Authenticate failed: %s", err)
			}
			claims := resp["claims"].(*jwtclaims.UserClaims)
			p.RoleMappers.Logger = logger
			p.RoleMappers.ApplyRoleMapToClaims(claims, backend.GetRealm())
			if len(claims.Roles) != len(expectedRoles) {
				// original code results in superadmin,anonymous,guest
				t.Errorf("Expected %d role (%s) got : %s",
					len(expectedRoles),
					strings.Join(expectedRoles, ","),
					strings.Join(claims.Roles, ","),
				)
			}
		}
	}

	{
		reqBackendRealm := "secondlocal"
		reqBackendMethod := "POST"

		opts := make(map[string]interface{})
		opts["auth_credentials"] = map[string]string{
			"username": "webadmin",
			"password": "password123",
		}

		expectedRoles := []string{
			"superadmin",
			"anonymous",
			"guest",
			"rolemapping_regex",
			"rolemapping_add",
			"fileadminlocaldomain",
			"secondlocal_regex",
			"secondlocal_add",
		}

		for _, backend := range p.Backends {
			if backend.GetRealm() != reqBackendRealm {
				continue
			}
			//opts["request"] = r
			opts["request_path"] = path.Join(p.AuthURLPath, reqBackendMethod, reqBackendRealm)
			resp, err := backend.Authenticate(opts)
			if err != nil {
				t.Errorf("Authenticate failed: %s", err)
			}
			claims := resp["claims"].(*jwtclaims.UserClaims)
			p.RoleMappers.Logger = logger
			p.RoleMappers.ApplyRoleMapToClaims(claims, backend.GetRealm())
			if len(claims.Roles) != len(expectedRoles) {
				// original code results in superadmin,anonymous,guest
				t.Errorf("Expected %d role (%s) got : %s",
					len(expectedRoles),
					strings.Join(expectedRoles, ","),
					strings.Join(claims.Roles, ","),
				)
			}
		}
	}

	time.Sleep(1 * time.Second)

	// faking it - the init() in portal.go is only going to be called once...
	core.PortalManager = &core.AuthPortalManager{}
}
