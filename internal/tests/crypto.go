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

package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"testing"
)

// GetCryptoKeyPair returns private-public key pair.
func GetCryptoKeyPair(t *testing.T, keyAlgo, publicKeyType string) (string, string) {
	switch keyAlgo {
	case "rsa":
	default:
		t.Fatalf("unsupported key algorithm: %s", keyAlgo)
	}
	switch publicKeyType {
	case "openssh", "rsa":
	default:
		t.Fatalf("unsupported public key type: %s", publicKeyType)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating private key: %v", err)
	}
	if err := privateKey.Validate(); err != nil {
		t.Fatalf("failed validating private key: %v", err)
	}
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	// t.Logf("private rsa key:\n%s", string(privateKeyPEM))

	switch publicKeyType {
	case "openssh":
		// Create OpenSSH formatted string
		publicKeyOpenSSH, err := ssh.NewPublicKey(privateKey.Public())
		if err != nil {
			t.Fatalf("failed creating openssh key: %v", err)
		}
		authorizedKeyBytes := ssh.MarshalAuthorizedKey(publicKeyOpenSSH)
		return string(privateKeyPEM), string(authorizedKeyBytes)
	}

	// Derive Public Key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatalf("failed creating rsa public key: %v", err)
	}
	// Create PEM encoded string
	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	return string(privateKeyPEM), string(publicKeyPEM)
}
