package registration

// Registration represent a common set of configuration settings for user registration
type Registration struct {
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
}
