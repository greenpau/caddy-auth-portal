package portal

import (
	"github.com/greenpau/caddy-auth-ui"
	"github.com/greenpau/go-identity"
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
	Realms             []ui.UserRealm         `json:"realms"`
}

// UserRegistrationParameters represent a common set of configuration settings
// for user registration
type UserRegistrationParameters struct {
	// The switch determining whether the registration is enabled/disabled.
	Disabled bool `json:"disabled,omitempty"`
	// The title of the registration page
	Title string `json:"title,omitempty"`
	// The mandatory registration code. It is possible adding multiple
	// codes, comma separated.
	Code string `json:"code,omitempty"`
	// The file path to registration database.
	Dropbox string `json:"dropbox,omitempty"`
	// The switch determining whether a user must accept terms and conditions
	RequireAcceptTerms bool `json:"require_accept_terms,omitempty"`
	// The switch determining whether the domain associated with an email has
	// a valid MX DNS record.
	RequireDomainMailRecord bool `json:"require_domain_mx,omitempty"`
	// User registration database
	db *identity.Database
}
