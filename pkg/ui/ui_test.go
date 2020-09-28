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
	if err := f.AddTemplate("login", "assets/templates/basic/login.template"); err != nil {
		t.Fatalf("Expected success, but got error: %s, %v", err, f.Templates)
	}

	t.Log("Rendering templates")
	args := f.GetArgs()
	var t1, t2 *bytes.Buffer
	var err error
	if t1, err = f.Render("basic/login", args); err != nil {
		t.Fatalf("Expected success, but got error: %s", err)
	}
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
