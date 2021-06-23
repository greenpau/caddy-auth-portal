// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cookie

import (
	"fmt"
	"strings"
)

// Config represents a common set of configuration settings
// applicable to the cookies issued by authn.Authenticator.
type Config struct {
	Domain   string `json:"domain,omitempty" xml:"domain,omitempty" yaml:"domain,omitempty"`
	Path     string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	Lifetime int    `json:"lifetime,omitempty" xml:"lifetime,omitempty" yaml:"lifetime,omitempty"`
	Insecure bool   `json:"insecure,omitempty" xml:"insecure,omitempty" yaml:"insecure,omitempty"`
	SameSite string `json:"same_site,omitempty" xml:"same_site,omitempty" yaml:"same_site,omitempty"`
}

// Factory holds configuration and associated finctions
// for the cookies issued by authn.Authenticator.
type Factory struct {
	config    *Config
	Referer   string `json:"referer,omitempty" xml:"referer,omitempty" yaml:"referer,omitempty"`
	SessionID string `json:"session_id,omitempty" xml:"session_id,omitempty" yaml:"session_id,omitempty"`
	SandboxID string `json:"sandbox_id,omitempty" xml:"sandbox_id,omitempty" yaml:"sandbox_id,omitempty"`
}

// NewFactory returns an instance of cookie factory.
func NewFactory(c *Config) (*Factory, error) {
	f := &Factory{}
	if c == nil {
		f.config = &Config{}
	} else {
		f.config = c
	}
	f.Referer = "AUTHP_REDIRECT_URL"
	f.SessionID = "AUTHP_SESSION_ID"
	f.SandboxID = "AUTHP_SANDBOX_ID"
	switch strings.ToLower(f.config.SameSite) {
	case "":
	case "lax", "strict", "none":
		f.config.SameSite = strings.Title(f.config.SameSite)
	default:
		return nil, fmt.Errorf("the SameSite cookie attribute %q is invalid", f.config.SameSite)
	}
	return f, nil
}

// GetCookie returns raw cookie string from key-value input.
func (f *Factory) GetCookie(k, v string) string {
	var sb strings.Builder
	sb.WriteString(k + "=" + v + ";")
	if f.config.Domain != "" {
		sb.WriteString(fmt.Sprintf(" Domain=%s;", f.config.Domain))
	}
	if f.config.Path != "" {
		sb.WriteString(fmt.Sprintf(" Path=%s;", f.config.Path))
	} else {
		sb.WriteString(" Path=/;")
	}
	if f.config.Lifetime != 0 {
		sb.WriteString(fmt.Sprintf(" Max-Age=%d;", f.config.Lifetime))
	}
	if f.config.SameSite != "" {
		sb.WriteString(fmt.Sprintf(" SameSite=%s;", f.config.SameSite))
	}
	if !f.config.Insecure {
		sb.WriteString(" Secure; HttpOnly;")
	}
	return sb.String()
}

// GetSessionCookie return cookie holding session information
func (f *Factory) GetSessionCookie(s string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s=%s;", f.SessionID, s))
	if f.config.Domain != "" {
		sb.WriteString(fmt.Sprintf(" Domain=%s;", f.config.Domain))
	}
	sb.WriteString(" Path=/;")
	if !f.config.Insecure {
		sb.WriteString(" Secure; HttpOnly;")
	}
	return sb.String()
}

// GetDeleteCookie returns raw cookie with attributes for delete action.
func (f *Factory) GetDeleteCookie(s string) string {
	var sb strings.Builder
	sb.WriteString(s)
	sb.WriteString("=delete;")
	if f.config.Domain != "" {
		sb.WriteString(fmt.Sprintf(" Domain=%s;", f.config.Domain))
	}
	if f.config.Path != "" {
		sb.WriteString(fmt.Sprintf(" Path=%s;", f.config.Path))
	} else {
		sb.WriteString(" Path=/;")
	}
	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}

// GetDeleteSessionCookie returns raw cookie with attributes for delete action
// for session id cookie.
func (f *Factory) GetDeleteSessionCookie() string {
	var sb strings.Builder
	sb.WriteString(f.SessionID)
	sb.WriteString("=delete;")
	if f.config.Domain != "" {
		sb.WriteString(fmt.Sprintf(" Domain=%s;", f.config.Domain))
	}
	sb.WriteString(" Path=/;")
	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}
