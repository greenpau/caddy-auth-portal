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
	"strings"
)

// Cookies represent a common set of configuration settings
// applicable to the cookies issued by the plugin.
type Cookies struct {
	Domain string `json:"domain,omitempty"`
	Path   string `json:"path,omitempty"`
}

// GetAttributes returns cookie attributes.
func (c *Cookies) GetAttributes() string {
	var sb strings.Builder
	if c.Domain != "" {
		sb.WriteString(" Domain=" + c.Domain + ";")
	}
	if c.Path != "" {
		sb.WriteString(" Path=" + c.Path + ";")
	} else {
		sb.WriteString(" Path=/;")
	}
	sb.WriteString(" Secure; HttpOnly;")
	return sb.String()
}

// GetDeleteAttributes returns cookie attributes for delete action.
func (c *Cookies) GetDeleteAttributes() string {
	var sb strings.Builder
	if c.Domain != "" {
		sb.WriteString(" Domain=" + c.Domain + ";")
	}
	if c.Path != "" {
		sb.WriteString(" Path=" + c.Path + ";")
	} else {
		sb.WriteString(" Path=/;")
	}
	return sb.String()
}
