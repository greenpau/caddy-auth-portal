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

package cookies

import (
	"fmt"
	"strings"
)

// Cookies represent a common set of configuration settings
// applicable to the cookies issued by the plugin.
type Cookies struct {
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Lifetime int    `json:"lifetime,omitempty"`
}

// GetCookie returns raw cookie string from key-value input.
func (c *Cookies) GetCookie(k, v string) string {
	var sb strings.Builder
	sb.WriteString(k + "=" + v + ";")
	if c.Domain != "" {
		sb.WriteString(" Domain=" + c.Domain + ";")
	}
	if c.Path != "" {
		sb.WriteString(" Path=" + c.Path + ";")
	} else {
		sb.WriteString(" Path=/;")
	}
	if c.Lifetime != 0 {
		sb.WriteString(" Max-Age=" + fmt.Sprint(c.Lifetime) + ";")
	}
	sb.WriteString(" Secure; HttpOnly;")
	return sb.String()
}

// GetDeleteCookie returns raw cookie with attributes for delete action.
func (c *Cookies) GetDeleteCookie(s string) string {
	var sb strings.Builder
	sb.WriteString(s)
	sb.WriteString("=delete;")
	if c.Domain != "" {
		sb.WriteString(" Domain=" + c.Domain + ";")
	}
	if c.Path != "" {
		sb.WriteString(" Path=" + c.Path + ";")
	} else {
		sb.WriteString(" Path=/;")
	}
	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}
