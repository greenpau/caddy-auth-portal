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
	"encoding/xml"
	"fmt"
	samllib "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

// Config holds the configuration for the Backend.
type Config struct {
	// Name is the unique name associated with the Backend..
	Name string `json:"name,omitempty"`
	// Method the name of the authentication method associated with the Backend.
	Method string `json:"method,omitempty"`
	// Realm the authentication realm associated with the Backend.
	Realm string `json:"realm,omitempty"`
	// Provider is the name of the provider associated with the Backend, e.g. azure.
	Provider string `json:"provider,omitempty"`
	// IdpMetadataLocation is the path to the Identity Provider metadata.
	IdpMetadataLocation string `json:"idp_metadata_location,omitempty"`
	// IdpSignCertLocation is the path to the Identity Provider signing certificate.
	IdpSignCertLocation string `json:"idp_sign_cert_location,omitempty"`
	// TenantID is the tenant ID associated with the Backend.
	TenantID string `json:"tenant_id,omitempty"`
	// ApplicationID is the application ID associated with the Backend.
	ApplicationID string `json:"application_id,omitempty"`
	// ApplicationName  is the application name associated with the Backend.
	ApplicationName string `json:"application_name,omitempty"`
	// EntityID is the "Identifier (Entity ID)" an administrator
	// specifies in "Set up Single Sign-On with SAML" in Azure AD
	// Enterprise Applications.
	EntityID string `json:"entity_id,omitempty"`
	// AssertionConsumerServiceURLs is the list of URLs server instance is listening
	// on. These URLs are known as SP Assertion Consumer Service endpoints. For
	// example, users may access a website via http://app.domain.local. At the
	// same time the users may access it by IP, e.g. http://10.10.10.10. or
	// by name, i.e. app. Each of the URLs is a separate endpoint.
	AssertionConsumerServiceURLs []string `json:"acs_urls,omitempty"`
}

// Configure configures Backend.
func (b *Backend) Configure() error {
	if b.Config.Name == "" {
		return errors.ErrBackendConfigureNameEmpty
	}
	if b.Config.Method == "" {
		return errors.ErrBackendConfigureMethodEmpty
	}
	if b.Config.Realm == "" {
		return errors.ErrBackendConfigureRealmEmpty
	}

	switch b.Config.Provider {
	case "azure":
		if b.Config.TenantID == "" {
			return fmt.Errorf("no tenant id found")
		}
		if b.Config.ApplicationID == "" {
			return fmt.Errorf("no application id found")
		}
		if b.Config.ApplicationName == "" {
			return fmt.Errorf("no application name found")
		}
		if b.Config.IdpMetadataLocation == "" {
			b.Config.IdpMetadataLocation = fmt.Sprintf(
				"https://login.microsoftonline.com/%s/federationmetadata/2007-06/federationmetadata.xml",
				b.Config.TenantID,
			)
		}
		b.loginURL = fmt.Sprintf(
			"https://account.activedirectory.windowsazure.com/applications/signin/%s/%s?tenantId=%s",
			b.Config.ApplicationName, b.Config.ApplicationID, b.Config.TenantID,
		)
	case "":
		return fmt.Errorf("no SAML provider found")
	default:
		return fmt.Errorf("unsupported SAML provider %s", b.Config.Provider)
	}

	if len(b.Config.AssertionConsumerServiceURLs) < 1 {
		return fmt.Errorf("ACS URLs are missing")
	}

	if b.Config.IdpSignCertLocation == "" {
		return fmt.Errorf("IdP Signing Certificate not found")
	}

	idpSignCert, err := utils.ReadCertFile(b.Config.IdpSignCertLocation)
	if err != nil {
		return err
	}

	// Obtain SAML IdP Metadata
	azureOptions := samlsp.Options{}
	if strings.HasPrefix(b.Config.IdpMetadataLocation, "http") {
		idpMetadataURL, err := url.Parse(b.Config.IdpMetadataLocation)
		if err != nil {
			return err
		}
		b.idpMetadataURL = idpMetadataURL
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
		metadataFileContent, err := ioutil.ReadFile(b.Config.IdpMetadataLocation)
		if err != nil {
			return err
		}
		idpMetadata, err := samlsp.ParseMetadata(metadataFileContent)
		if err != nil {
			return err
		}
		azureOptions.IDPMetadata = idpMetadata
	}

	b.serviceProviders = make(map[string]*samllib.ServiceProvider)
	for _, acsURL := range b.Config.AssertionConsumerServiceURLs {
		sp := samlsp.DefaultServiceProvider(azureOptions)
		sp.AllowIDPInitiated = true
		//sp.EntityID = sp.IDPMetadata.EntityID

		cfgAcsURL, _ := url.Parse(acsURL)
		sp.AcsURL = *cfgAcsURL

		entityID, _ := url.Parse(b.Config.EntityID)
		sp.MetadataURL = *entityID

		if b.idpMetadataURL != nil {
			sp.MetadataURL = *b.idpMetadataURL
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

		b.serviceProviders[acsURL] = &sp
	}

	b.logger.Info(
		"successfully configured SAML backend",
		zap.String("tenant_id", b.Config.TenantID),
		zap.String("application_id", b.Config.ApplicationID),
		zap.String("application_name", b.Config.ApplicationName),
		zap.Any("acs_urls", b.Config.AssertionConsumerServiceURLs),
		zap.String("login_url", b.loginURL),
		zap.String("idp_sign_cert_location", b.Config.IdpSignCertLocation),
		zap.String("idp_metadata_location", b.Config.IdpMetadataLocation),
	)

	return nil
}

// ValidateConfig checks whether Backend has mandatory configuration.
func (b *Backend) ValidateConfig() error {
	return nil
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

// ConfigureLogger configures backend with the same logger as its user.
func (b *Backend) ConfigureLogger(logger *zap.Logger) error {
	if logger == nil {
		return fmt.Errorf("upstream logger is nil")
	}
	b.logger = logger
	return nil
}

// GetConfig returns Backend configuration.
func (b *Backend) GetConfig() string {
	var sb strings.Builder
	sb.WriteString("name " + b.Config.Name + "\n")
	sb.WriteString("method " + b.Config.Method + "\n")
	sb.WriteString("realm " + b.Config.Realm + "\n")
	sb.WriteString("provider " + b.Config.Provider)
	return sb.String()
}
