package forms

import (
	"github.com/greenpau/caddy-auth-ui"
)

// UserInterfaceParameters represent a common set of configuration settings
// for HTML UI.
type UserInterfaceParameters struct {
	Templates          map[string]string      `json:"templates,omitempty"`
	AllowRoleSelection bool                   `json:"allow_role_selection,omitempty"`
	Title              string                 `json:"title,omitempty"`
	LogoURL            string                 `json:"logo_url,omitempty"`
	LogoDescription    string                 `json:"logo_description,omitempty"`
	PrivateLinks       []ui.UserInterfaceLink `json:"private_links,omitempty"`
	AutoRedirectURL    string                 `json:"auto_redirect_url"`
}
