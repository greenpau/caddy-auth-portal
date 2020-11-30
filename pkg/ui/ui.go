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

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path"
	"strings"
	"text/template"
)

// Themes stores UI themes.
var Themes = map[string]interface{}{
	"basic": true,
}

// UserInterfaceFactory represents a collection of HTML templates
// and associated methods for the creation of HTML user interfaces.
type UserInterfaceFactory struct {
	//TemplatePrefix  string                            `json:"template_prefix,omitempty"`
	Templates               map[string]*UserInterfaceTemplate `json:"templates,omitempty"`
	Title                   string                            `json:"title,omitempty"`
	LogoURL                 string                            `json:"logo_url,omitempty"`
	LogoDescription         string                            `json:"logo_description,omitempty"`
	RegistrationEnabled     bool                              `json:"registration_enabled,omitempty"`
	PasswordRecoveryEnabled bool                              `json:"password_recovery_enabled,omitempty"`
	MfaEnabled              bool                              `json:"mfa_enabled,omitempty"`
	// The links visible to anonymoous user
	PublicLinks []UserInterfaceLink `json:"public_links,omitempty"`
	// The links visible to authenticated user
	PrivateLinks []UserInterfaceLink `json:"private_links,omitempty"`
	// The authentication realms/domains
	Realms []UserRealm `json:"realms,omitempty"`
	// The pass to authentication endpoint. This is where
	// user credentials will be passed to via POST.
	ActionEndpoint string `json:"-"`
	CustomCSSPath  string `json:"custom_css_path,omitempty"`
	CustomJsPath   string `json:"custom_js_path,omitempty"`
}

// UserInterfaceTemplate represents a user interface instance, e.g. a single
// HTML page.
type UserInterfaceTemplate struct {
	Alias string `json:"alias,omitempty"`
	// Path could be `inline`, URL path, or file path
	Path     string             `json:"path,omitempty"`
	Template *template.Template `json:"-"`
}

// UserRealm represents a single authentication realm/domain.
type UserRealm struct {
	Name  string `json:"name,omitempty"`
	Label string `json:"label,omitempty"`
}

// UserInterfaceArgs is a collection of page attributes
// that needs to be passed to Render method.
type UserInterfaceArgs struct {
	Title                   string
	LogoURL                 string
	LogoDescription         string
	ActionEndpoint          string
	Message                 string
	MessageType             string
	PublicLinks             []UserInterfaceLink
	PrivateLinks            []UserInterfaceLink
	Realms                  []UserRealm
	Authenticated           bool
	Data                    map[string]interface{}
	RegistrationEnabled     bool
	PasswordRecoveryEnabled bool
	MfaEnabled              bool
	CustomCSSEnabled        bool
	CustomJsEnabled         bool
}

// NewUserInterfaceFactory return an instance of a user interface factory.
func NewUserInterfaceFactory() *UserInterfaceFactory {
	return &UserInterfaceFactory{
		LogoURL:         "assets/images/logo.svg",
		LogoDescription: "Authentication Portal",
		Templates:       make(map[string]*UserInterfaceTemplate),
		PublicLinks:     []UserInterfaceLink{},
		PrivateLinks:    []UserInterfaceLink{},
		Realms:          []UserRealm{},
	}
}

// NewUserInterfaceTemplate returns a user interface template
func NewUserInterfaceTemplate(s, tp string) (*UserInterfaceTemplate, error) {
	var templateBody string
	if s == "" {
		return nil, fmt.Errorf("the user interface alias cannot be empty")
	}
	if tp == "" {
		return nil, fmt.Errorf("the path to user interface template cannot be empty")
	}
	tmpl := &UserInterfaceTemplate{
		Alias: s,
		Path:  tp,
	}

	if tp == "inline" {
		if _, exists := PageTemplates[s]; !exists {
			return nil, fmt.Errorf("built-in template does not exists: %s", s)
		}
		templateBody = PageTemplates[s]
	} else {
		if strings.HasPrefix(tp, "http://") || strings.HasPrefix(tp, "https://") {
			return nil, fmt.Errorf("the loading of template from remote URL is not supported yet")
		}
		// Assuming the template is a file system template
		content, err := ioutil.ReadFile(tp)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s template from %s: %s", s, tp, err)
		}
		templateBody = string(content)
	}

	t, err := loadTemplateFromString(s, templateBody)
	if err != nil {
		return nil, fmt.Errorf("Failed to load %s template from %s: %s", s, tp, err)
	}
	tmpl.Template = t
	return tmpl, nil
}

// GetArgs return an instance of UserInterfaceArgs. Upon the receipt
// of the arguments, they can be manipulated and passed to
// UserInterfaceFactory.Render method. The manipulation means
// adding an error message, appending to the title of a page,
// adding arbitrary data etc.
func (f *UserInterfaceFactory) GetArgs() *UserInterfaceArgs {
	args := &UserInterfaceArgs{
		Title:                   f.Title,
		LogoURL:                 f.LogoURL,
		LogoDescription:         f.LogoDescription,
		PublicLinks:             f.PublicLinks,
		PrivateLinks:            f.PrivateLinks,
		Realms:                  f.Realms,
		ActionEndpoint:          f.ActionEndpoint,
		Data:                    make(map[string]interface{}),
		RegistrationEnabled:     f.RegistrationEnabled,
		PasswordRecoveryEnabled: f.PasswordRecoveryEnabled,
		MfaEnabled:              f.MfaEnabled,
	}
	uiOptions := make(map[string]interface{})
	if f.CustomCSSPath != "" {
		args.CustomCSSEnabled = true
		uiOptions["custom_css_required"] = "yes"
	} else {
		uiOptions["custom_css_required"] = "no"
	}

	if f.CustomJsPath != "" {
		args.CustomJsEnabled = true
		uiOptions["custom_js_required"] = "yes"
	} else {
		uiOptions["custom_js_required"] = "no"
	}
	args.Data["ui_options"] = uiOptions
	return args
}

// AddBuiltinTemplates adds all built-in template to UserInterfaceFactory
func (f *UserInterfaceFactory) AddBuiltinTemplates() error {
	for name := range PageTemplates {
		if err := f.AddBuiltinTemplate(name); err != nil {
			return fmt.Errorf("Failed to load built-in template %s: %s", name, err)
		}
	}
	return nil
}

// AddBuiltinTemplate adds a built-in template to UserInterfaceFactory
func (f *UserInterfaceFactory) AddBuiltinTemplate(name string) error {
	if _, exists := f.Templates[name]; exists {
		return fmt.Errorf("template %s already defined", name)
	}
	if _, exists := PageTemplates[name]; !exists {
		return fmt.Errorf("built-in template %s does not exists", name)
	}
	tmpl, err := NewUserInterfaceTemplate(name, "inline")
	if err != nil {
		return err
	}
	f.Templates[name] = tmpl
	return nil
}

// AddTemplate adds a template to UserInterfaceFactory.
func (f *UserInterfaceFactory) AddTemplate(s, tp string) error {
	if _, exists := f.Templates[s]; exists {
		return fmt.Errorf("Template already defined: %s", s)
	}
	tmpl, err := NewUserInterfaceTemplate(s, tp)
	if err != nil {
		return err
	}
	f.Templates[s] = tmpl
	return nil
}

// DeleteTemplates removes all templates from UserInterfaceFactory.
func (f *UserInterfaceFactory) DeleteTemplates() {
	f.Templates = make(map[string]*UserInterfaceTemplate)
	return
}

func loadTemplateFromString(s, p string) (*template.Template, error) {
	funcMap := template.FuncMap{
		"pathjoin": path.Join,
	}
	t := template.New(s).Funcs(funcMap)
	t, err := t.Parse(p)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Render returns a pointer to a data buffer.
func (f *UserInterfaceFactory) Render(name string, args *UserInterfaceArgs) (*bytes.Buffer, error) {
	if _, exists := f.Templates[name]; !exists {
		return nil, fmt.Errorf("template %s does not exist", name)
	}
	b := bytes.NewBuffer(nil)
	err := f.Templates[name].Template.Execute(b, args)
	if err != nil {
		return nil, err
	}
	return b, nil
}
