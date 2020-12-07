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

package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	samllib "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"github.com/greenpau/go-identity"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
	"go.uber.org/zap"
)

// Backend represents authentication provider with SAML backend.
type Backend struct {
	Name     string `json:"name,omitempty"`
	Method   string `json:"method,omitempty"`
	Realm    string `json:"realm,omitempty"`
	Provider string `json:"provider,omitempty"`

	ServiceProviders    map[string]*samllib.ServiceProvider `json:"-"`
	IdpMetadataLocation string                              `json:"idp_metadata_location,omitempty"`
	IdpMetadataURL      *url.URL                            `json:"-"`
	IdpSignCertLocation string                              `json:"idp_sign_cert_location,omitempty"`
	TenantID            string                              `json:"tenant_id,omitempty"`
	ApplicationID       string                              `json:"application_id,omitempty"`
	ApplicationName     string                              `json:"application_name,omitempty"`

	// LoginURL is the link to Azure AD authentication portal.
	// The link is auto-generated based on Azure AD tenant and
	// application IDs.
	LoginURL string `json:"-"`
	// EntityID is the "Identifier (Entity ID)" an administrator
	// specifies in "Set up Single Sign-On with SAML" in Azure AD
	// Enterprise Applications.
	EntityID string `json:"entity_id,omitempty"`
	// AcsURL is the list of URLs server instance is listening on. These URLS
	// are known as SP Assertion Consumer Service endpoints. For example,
	// users may access a website via http://app.domain.local. At the
	// same time the users may access it by IP, e.g. http://10.10.10.10. or
	// by name, i.e. app. Each of the URLs is a separate endpoint.
	AssertionConsumerServiceURLs []string `json:"acs_urls,omitempty"`

	TokenProvider *jwtconfig.CommonTokenConfig `json:"-"`
	logger        *zap.Logger
}

// NewDatabaseBackend return an instance of authentication provider
// with SAML backend.
func NewDatabaseBackend() *Backend {
	b := &Backend{
		Method:        "saml",
		TokenProvider: jwtconfig.NewCommonTokenConfig(),
	}
	return b
}

// ConfigureAuthenticator configures backend authenticator.
func (b *Backend) ConfigureAuthenticator() error {
	if b.Realm == "" {
		return fmt.Errorf("no realm found")
	}

	switch b.Provider {
	case "azure":
		if b.TenantID == "" {
			return fmt.Errorf("no tenant id found")
		}
		if b.ApplicationID == "" {
			return fmt.Errorf("no application id found")
		}
		if b.ApplicationName == "" {
			return fmt.Errorf("no application name found")
		}
		if b.IdpMetadataLocation == "" {
			b.IdpMetadataLocation = fmt.Sprintf(
				"https://login.microsoftonline.com/%s/federationmetadata/2007-06/federationmetadata.xml",
				b.TenantID,
			)
		}
		b.LoginURL = fmt.Sprintf(
			"https://account.activedirectory.windowsazure.com/applications/signin/%s/%s?tenantId=%s",
			b.ApplicationName, b.ApplicationID, b.TenantID,
		)
	case "":
		return fmt.Errorf("no SAML provider found")
	default:
		return fmt.Errorf("unsupported SAML provider %s", b.Provider)
	}

	if len(b.AssertionConsumerServiceURLs) < 1 {
		return fmt.Errorf("ACS URLs are missing")
	}

	if b.IdpSignCertLocation == "" {
		return fmt.Errorf("IdP Signing Certificate not found")
	}

	idpSignCert, err := utils.ReadCertFile(b.IdpSignCertLocation)
	if err != nil {
		return err
	}

	// Obtain SAML IdP Metadata
	azureOptions := samlsp.Options{}
	if strings.HasPrefix(b.IdpMetadataLocation, "http") {
		idpMetadataURL, err := url.Parse(b.IdpMetadataLocation)
		if err != nil {
			return err
		}
		b.IdpMetadataURL = idpMetadataURL
		azureOptions.URL = *idpMetadataURL
		idpMetadata, err := samlsp.FetchMetadata(
			context.Background(),
			http.DefaultClient,
			*idpMetadataURL,
		)
		if err != nil {
			return err
		}
		azureOptions.IDPMetadata = idpMetadata
	} else {
		metadataFileContent, err := ioutil.ReadFile(b.IdpMetadataLocation)
		if err != nil {
			return err
		}
		idpMetadata, err := samlsp.ParseMetadata(metadataFileContent)
		if err != nil {
			return err
		}
		azureOptions.IDPMetadata = idpMetadata
	}

	b.ServiceProviders = make(map[string]*samllib.ServiceProvider)
	for _, acsURL := range b.AssertionConsumerServiceURLs {
		sp := samlsp.DefaultServiceProvider(azureOptions)
		sp.AllowIDPInitiated = true
		//sp.EntityID = sp.IDPMetadata.EntityID

		cfgAcsURL, _ := url.Parse(acsURL)
		sp.AcsURL = *cfgAcsURL

		entityID, _ := url.Parse(b.EntityID)
		sp.MetadataURL = *entityID

		if b.IdpMetadataURL != nil {
			sp.MetadataURL = *b.IdpMetadataURL
		}

		for i := range sp.IDPMetadata.IDPSSODescriptors {
			idpSSODescriptor := &sp.IDPMetadata.IDPSSODescriptors[i]
			keyDescriptor := &samllib.KeyDescriptor{
				Use: "signing",
				KeyInfo: samllib.KeyInfo{
					XMLName: xml.Name{
						Space: "http://www.w3.org/2000/09/xmldsig#",
						Local: "KeyInfo",
					},
					Certificate: idpSignCert,
				},
			}
			idpSSODescriptor.KeyDescriptors = append(idpSSODescriptor.KeyDescriptors, *keyDescriptor)
			break
		}

		b.ServiceProviders[acsURL] = &sp
	}

	b.logger.Info(
		"successfully configured SAML backend",
		zap.String("tenant_id", b.TenantID),
		zap.String("application_id", b.ApplicationID),
		zap.String("application_name", b.ApplicationName),
		zap.Any("acs_urls", b.AssertionConsumerServiceURLs),
		zap.String("login_url", b.LoginURL),
		zap.String("idp_sign_cert_location", b.IdpSignCertLocation),
		zap.String("idp_metadata_location", b.IdpMetadataLocation),
	)

	return nil
}

// ValidateConfig checks whether Backend has mandatory configuration.
func (b *Backend) ValidateConfig() error {
	return nil
}

// Authenticate performs authentication.
func (b *Backend) Authenticate(opts map[string]interface{}) (map[string]interface{}, error) {
	r := opts["request"].(*http.Request)
	reqID := opts["request_id"].(string)
	resp := make(map[string]interface{})
	resp["code"] = 400
	if r.Method != "POST" {
		resp["code"] = 200
		resp["redirect_url"] = b.LoginURL
		return resp, nil
	}

	if r.ContentLength > 30000 {
		return resp, fmt.Errorf("Request payload exceeded the limit of 30,000 bytes: %d", r.ContentLength)
	}
	if r.ContentLength < 500 {
		return resp, fmt.Errorf("Request payload is too small: %d", r.ContentLength)
	}
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/x-www-form-urlencoded" {
		return resp, fmt.Errorf("Request content type is not application/x-www-form-urlencoded")
	}
	if err := r.ParseForm(); err != nil {
		return resp, fmt.Errorf("Failed to parse form: %s", err)
	}
	if r.FormValue("SAMLResponse") == "" {
		return resp, fmt.Errorf("Request payload has no SAMLResponse field")
	}
	samlResponseBytes, err := base64.StdEncoding.DecodeString(r.FormValue("SAMLResponse"))
	if err != nil {
		return resp, err
	}
	acsURL := ""
	s := string(samlResponseBytes)
	for _, elem := range []string{"Destination=\""} {
		i := strings.Index(s, elem)
		if i < 0 {
			continue
		}
		j := strings.Index(s[i+len(elem):], "\"")
		if j < 0 {
			continue
		}
		acsURL = s[i+len(elem) : i+len(elem)+j]
	}

	if acsURL == "" {
		return resp, fmt.Errorf("Failed to parse ACS URL")
	}

	if b.Provider == "azure" {
		if !strings.Contains(r.Header.Get("Origin"), "login.microsoftonline.com") &&
			!strings.Contains(r.Header.Get("Referer"), "windowsazure.com") {
			return resp, fmt.Errorf("Origin does not contain login.microsoftonline.com and Referer is not windowsazure.com")
		}
	}

	sp, serviceProviderExists := b.ServiceProviders[acsURL]
	if !serviceProviderExists {
		return resp, fmt.Errorf("Unsupported ACS URL %s", acsURL)
	}

	samlAssertions, err := sp.ParseXMLResponse(samlResponseBytes, []string{""})
	if err != nil {
		return resp, fmt.Errorf("Failed to ParseXMLResponse: %s", err)
	}

	claims := &jwtclaims.UserClaims{}

	foundAttr := make(map[string]interface{})

	for _, attrStatement := range samlAssertions.AttributeStatements {
		for _, attrEntry := range attrStatement.Attributes {
			if len(attrEntry.Values) == 0 {
				continue
			}
			if strings.HasSuffix(attrEntry.Name, "Attributes/MaxSessionDuration") {
				multiplier, err := strconv.Atoi(attrEntry.Values[0].Value)
				if err != nil {
					b.logger.Error(
						"Failed parsing Attributes/MaxSessionDuration",
						zap.String("request_id", reqID),
						zap.String("error", err.Error()),
					)
					continue
				}
				claims.ExpiresAt = time.Now().Add(time.Duration(multiplier) * time.Second).Unix()
				foundAttr["exp"] = true
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "identity/claims/displayname") {
				claims.Name = attrEntry.Values[0].Value
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "identity/claims/emailaddress") {
				claims.Email = attrEntry.Values[0].Value
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "identity/claims/identityprovider") {
				claims.Origin = attrEntry.Values[0].Value
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "identity/claims/name") {
				claims.Subject = attrEntry.Values[0].Value
				continue
			}

			if strings.HasSuffix(attrEntry.Name, "Attributes/Role") {
				for _, attrEntryElement := range attrEntry.Values {
					claims.Roles = append(claims.Roles, attrEntryElement.Value)
				}
				continue
			}
		}
	}

	if claims.Email == "" || claims.Name == "" {
		return resp, fmt.Errorf("The Azure AD authorization failed, mandatory attributes not found: %v", claims)
	}

	if len(claims.Roles) == 0 {
		claims.Roles = append(claims.Roles, "anonymous")
	}

	if claims.Origin == "" {
		claims.Origin = b.TokenProvider.TokenOrigin
	}

	if _, found := foundAttr["exp"]; !found {
		claims.ExpiresAt = time.Now().Add(time.Duration(b.TokenProvider.TokenLifetime) * time.Second).Unix()
	}

	claims.IssuedAt = time.Now().Unix()
	resp["claims"] = claims
	return resp, nil
}

// Validate checks whether Backend is functional.
func (b *Backend) Validate() error {
	if err := b.ValidateConfig(); err != nil {
		return err
	}
	if b.logger == nil {
		return fmt.Errorf("SAML backend logger is nil")
	}

	b.logger.Info("successfully validated SAML backend")
	return nil
}

// GetRealm return authentication realm.
func (b *Backend) GetRealm() string {
	return b.Realm
}

// GetName return the name associated with this backend.
func (b *Backend) GetName() string {
	return b.Name
}

// ConfigureTokenProvider configures TokenProvider.
func (b *Backend) ConfigureTokenProvider(upstream *jwtconfig.CommonTokenConfig) error {
	if upstream == nil {
		return fmt.Errorf("upstream token provider is nil")
	}
	if b.TokenProvider == nil {
		b.TokenProvider = jwtconfig.NewCommonTokenConfig()
	}
	if b.TokenProvider.TokenSecret == "" {
		b.TokenProvider.TokenSecret = upstream.TokenSecret
	}
	if b.TokenProvider.TokenOrigin == "" {
		b.TokenProvider.TokenOrigin = upstream.TokenOrigin
	}
	b.TokenProvider.TokenLifetime = upstream.TokenLifetime
	b.TokenProvider.TokenName = upstream.TokenName
	return nil
}

// ConfigureLogger configures backend with the same logger as its user.
func (b *Backend) ConfigureLogger(logger *zap.Logger) error {
	if logger == nil {
		return fmt.Errorf("upstream logger is nil")
	}
	b.logger = logger
	return nil
}

// GetMethod returns the authentication method associated with this backend.
func (b *Backend) GetMethod() string {
	return b.Method
}

// Do performs the requested operation.
func (b *Backend) Do(opts map[string]interface{}) error {
	op := opts["name"].(string)
	switch op {
	case "password_change":
		return fmt.Errorf("Password change operation is not available")
	}
	return fmt.Errorf("Unsupported backend operation")
}

// GetPublicKeys return a list of public keys associated with a user.
func (b *Backend) GetPublicKeys(opts map[string]interface{}) ([]*identity.PublicKey, error) {
	return nil, fmt.Errorf("Unsupported backend operation")
}

// GetMfaTokens return a list of MFA tokens associated with a user.
func (b *Backend) GetMfaTokens(opts map[string]interface{}) ([]*identity.MfaToken, error) {
	return nil, fmt.Errorf("Unsupported backend operation")
}
