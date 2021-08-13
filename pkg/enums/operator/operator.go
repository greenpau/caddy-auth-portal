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

package operator

import (
	"fmt"
)

// Type is the type of an operator.
type Type int

const (
	// Unknown operator signals invalid operator.
	Unknown Type = iota
	// Authenticate operator signals authentication request.
	Authenticate
	// ChangePassword operator signals the changing of password.
	ChangePassword
	// GetPublicKeys operator signals the retrieval of public keys.
	GetPublicKeys
	// GetAPIKeys operator signals the retrieval of API keys.
	GetAPIKeys
	// AddKeySSH operator signals the addition of an SSH public key.
	AddKeySSH
	// AddKeyGPG operator signals the addition of an GPG public key.
	AddKeyGPG
	// AddAPIKey operator signals the addition of an API key.
	AddAPIKey
	// DeletePublicKey operator signals the deletion of a public key.
	DeletePublicKey
	// DeleteAPIKey operator signals the deletion of an API key.
	DeleteAPIKey
	// GetMfaTokens operator signals the retrieval of MFA tokens.
	GetMfaTokens
	// AddMfaToken operator signals the addition of an MFA token.
	AddMfaToken
	// DeleteMfaToken operator signals the deletion of an MFA token.
	DeleteMfaToken
	// GetUsers operator signals the retrieval of users.
	GetUsers
	// GetUser operator signals the retrieval of a specific user.
	GetUser
	// AddUser operator signals the addition of a user.
	AddUser
	// DeleteUser operator signals the deletion of a user.
	DeleteUser
)

// String returns string representation of an operator.
func (e Type) String() string {
	switch e {
	case Unknown:
		return "Unknown"
	case Authenticate:
		return "Authenticate"
	case ChangePassword:
		return "ChangePassword"
	case GetPublicKeys:
		return "GetPublicKeys"
	case AddKeySSH:
		return "AddKeySSH"
	case AddKeyGPG:
		return "AddKeyGPG"
	case DeletePublicKey:
		return "DeletePublicKey"
	case GetMfaTokens:
		return "GetMfaTokens"
	case AddMfaToken:
		return "AddMfaToken"
	case DeleteMfaToken:
		return "DeleteMfaToken"
	case GetUsers:
		return "GetUsers"
	case GetUser:
		return "GetUser"
	case AddUser:
		return "AddUser"
	case DeleteUser:
		return "DeleteUser"
	case GetAPIKeys:
		return "GetAPIKeys"
	case AddAPIKey:
		return "AddAPIKey"
	case DeleteAPIKey:
		return "DeleteAPIKey"
	}
	return fmt.Sprintf("Type(%d)", int(e))
}
