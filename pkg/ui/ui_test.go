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
	"strings"
	"testing"
)

func TestNewUserInterface(t *testing.T) {
	t.Log("Creating UI factory")
	f := NewUserInterfaceFactory()
	f.Title = "Authentication"
	f.LogoURL = "/images/logo.png"
	f.LogoDescription = "Authentication Portal"
	officeLink := UserInterfaceLink{
		Title: "Office 365",
		Link:  "https://office.com/",
		Style: "fa-windows",
	}
	f.PublicLinks = append(f.PublicLinks, officeLink)
	f.PrivateLinks = append(f.PrivateLinks, UserInterfaceLink{
		Title: "Prometheus",
		Link:  "/prometheus",
	})
	f.PrivateLinks = append(f.PrivateLinks, UserInterfaceLink{
		Title: "Alertmanager",
		Link:  "/alertmanager",
	})
	f.ActionEndpoint = "/auth/login"

	t.Log("Adding a built-in template")
	if err := f.AddBuiltinTemplate("basic/login"); err != nil {
		t.Fatalf("Expected success, but got error: %s, %v", err, f.Templates)
	}

	t.Log("Adding a template from file system")
	if err := f.AddTemplate("login", "../../assets/templates/basic/login.template"); err != nil {
		t.Fatalf("Expected success, but got error: %s, %v", err, f.Templates)
	}

	loginRealm := make(map[string]string)
	loginRealm["realm"] = "local"
	loginRealm["label"] = strings.ToTitle("Local")
	loginRealm["default"] = "yes"

	var loginRealms []map[string]string
	loginRealms = append(loginRealms, loginRealm)

	loginOptions := make(map[string]interface{})
	loginOptions["form_required"] = "yes"
	loginOptions["realm_dropdown_required"] = "no"
	loginOptions["username_required"] = "yes"
	loginOptions["password_required"] = "yes"
	loginOptions["external_providers_required"] = "no"
	loginOptions["registration_required"] = "no"
	loginOptions["password_recovery_required"] = "no"
	loginOptions["realms"] = loginRealms

	t.Log("Rendering templates")
	args := f.GetArgs()
	args.Data["login_options"] = loginOptions

	var t1, t2 *bytes.Buffer
	var err error
	if t1, err = f.Render("basic/login", args); err != nil {
		t.Fatalf("Expected success, but got error: %s", err)
	}

	args = f.GetArgs()
	args.Data["login_options"] = loginOptions
	if t2, err = f.Render("login", args); err != nil {
		t.Fatalf("Expected success, but got error: %s", err)
	}
	if strings.TrimSpace(t1.String()) != strings.TrimSpace(t2.String()) {
		t.Fatalf("Expected templates to match, but got mismatch: %d (basic/login) vs. %d (login)", t1.Len(), t2.Len())
	}

}

func TestAddBuiltinTemplates(t *testing.T) {
	var expError string
	t.Logf("Creating UI factory")
	f := NewUserInterfaceFactory()

	t.Logf("Adding templates")
	if err := f.AddBuiltinTemplates(); err != nil {
		t.Fatal(err)
	}

	if err := f.AddBuiltinTemplate("saml"); err != nil {
		expError = "built-in template saml does not exists"
		if err.Error() != expError {
			t.Fatalf("Mismatch between errors: %s (received) vs. %s (expected)", err.Error(), expError)
		}
	} else {
		t.Fatalf("Expected an error, but got success")
	}

	t.Logf("Purging templates")
	f.DeleteTemplates()

	t.Logf("Re-adding templates")
	if err := f.AddBuiltinTemplate("basic/login"); err != nil {
		t.Fatalf("Expected success, but got error: %s", err)
	}

	t.Logf("Purging templates")
	f.DeleteTemplates()

	t.Logf("Re-adding templates")
	if err := f.AddBuiltinTemplate("basic/login"); err != nil {
		t.Fatalf("Expected success, but got error: %s", err)
	}

	t.Logf("Purging templates")
	f.DeleteTemplates()

	t.Logf("Re-adding templates")
	if err := f.AddBuiltinTemplate("basic/portal"); err != nil {
		t.Fatalf("Expected success, but got error: %s", err)
	}
}
