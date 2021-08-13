// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package errors

// Portal errors.
const (
	ErrTooManyPrimaryInstances               StandardError = "found more than one primaryInstance instance of the plugin for %s context"
	ErrStaticAssetAddFailed                  StandardError = "failed adding custom static asset %s (%s) from %s for %s instance in %s context failed to load: %v"
	ErrUserRegistrationSetupFailed           StandardError = "user registration setup for %s instance in %s context failed: %v"
	ErrUserRegistrationMetadataReadFailed    StandardError = "user registration metadata read for %s instance in %s context failed: %v"
	ErrUserRegistrationDropboxBadPath        StandardError = "user registration dropbox for %s instance in %s is a directory"
	ErrUserRegistrationDropboxLoadFailed     StandardError = "user registration dropbox for %s instance in %s context failed to load: %v"
	ErrUserInterfaceThemeNotFound            StandardError = "user interface validation for %s instance in %s context failed: %s theme not found"
	ErrUserInterfaceBuiltinTemplateAddFailed StandardError = "user interface validation for %s instance in %s context failed for built-in template %s in %s theme: %v"
	ErrUserInterfaceCustomTemplateAddFailed  StandardError = "user interface validation for %s instance in %s context failed for custom template %s in %s: %v"
	ErrUserRegistrationConfig                StandardError = "user registration configuration for %q instance failed: %v"
	ErrCryptoKeyStoreConfig                  StandardError = "crypto key store configuration for %q instance failed: %v"
	ErrInstanceManagerValidate               StandardError = "instance %q validation failed: %v"
	ErrGeneric                               StandardError = "%s: %v"
)
