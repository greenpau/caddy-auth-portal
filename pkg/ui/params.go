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

package ui

// UserInterfaceParameters represent a common set of configuration settings
// for HTML UI.
type UserInterfaceParameters struct {
	Theme                   string              `json:"theme,omitempty"`
	Templates               map[string]string   `json:"templates,omitempty"`
	AllowRoleSelection      bool                `json:"allow_role_selection,omitempty"`
	Title                   string              `json:"title,omitempty"`
	LogoURL                 string              `json:"logo_url,omitempty"`
	LogoDescription         string              `json:"logo_description,omitempty"`
	PrivateLinks            []UserInterfaceLink `json:"private_links,omitempty"`
	AutoRedirectURL         string              `json:"auto_redirect_url"`
	Realms                  []UserRealm         `json:"realms"`
	PasswordRecoveryEnabled bool                `json:"password_recovery_enabled"`
	CustomCSSPath           string              `json:"custom_css_path,omitempty"`
	CustomJsPath            string              `json:"custom_js_path,omitempty"`
}
