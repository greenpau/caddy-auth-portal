package portal

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestCaddyfile(t *testing.T) {
	baseURL := "http://localhost:9080"
	localhost, _ := url.Parse(baseURL)
	tester := caddytest.NewTester(t)
	tester.InitServer(`
    {
      http_port     9080
      https_port    9443
      order auth_portal after rewrite
    }

    localhost:9080 {
	  route /auth* {
        auth_portal {
          path /auth
          backends {
            local_backend {
              type local
              file /etc/gatekeeper/auth/local/users.json
              realm local
            }
          }
          jwt {
            token_name access_token
            token_secret 0e2fdcf8-6868-41a7-884b-7308795fc286
            token_issuer e1008f2d-ccfa-4e62-bbe6-c202ec2988cc
          }
          ui {
            login_template "/etc/gatekeeper/ui/forms_login.template"
            portal_template "/etc/gatekeeper/ui/forms_portal.template"
            logo_url "https://caddyserver.com/resources/images/caddy-circle-lock.svg"
            logo_description "Caddy"
          }
        }
      }

      route /public* {
        respond * "public" 200
      }

      route {
        redir https://{hostport}/auth 302
      }
    }
    `, "caddyfile")

	tester.AssertGetResponse(baseURL+"/auth/whoami", 200, "greenpau")

	cookies := []*http.Cookie{}
	cookie := &http.Cookie{
		Name:  "access_code",
		Value: "anonymous",
	}

	cookies = append(cookies, cookie)
	tester.Client.Jar.SetCookies(localhost, cookies)
	tester.AssertGetResponse(baseURL+"/auth/whoami?format=raw&field=username", 200, "greenpau")
}
