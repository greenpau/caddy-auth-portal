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

package oauth2

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
)

// JwksKey is a JSON object that represents a cryptographic key.
// See https://tools.ietf.org/html/rfc7517#section-4,
// https://tools.ietf.org/html/rfc7518#section-6.3
type JwksKey struct {
	Algorithm    string `json:"alg,omitempty"`
	Exponent     string `json:"e,omitempty"`
	KeyID        string `json:"kid,omitempty"`
	KeyType      string `json:"kty,omitempty"`
	Modulus      string `json:"n,omitempty"`
	PublicKeyUse string `json:"use,omitempty"`
	publicKey    *rsa.PublicKey
}

// Validate returns error if JwksKey does not contain relevant information.
func (k *JwksKey) Validate() error {
	if k.KeyID == "" {
		return fmt.Errorf("key id is empty")
	}
	switch k.Algorithm {
	case "RS256", "RS384", "RS512", "":
	default:
		return fmt.Errorf("unsupported key algorithm %s for %s", k.Algorithm, k.KeyID)
	}
	switch k.KeyType {
	case "RSA":
	case "":
		return fmt.Errorf("key type is empty for %s", k.KeyID)
	default:
		return fmt.Errorf("unsupported key type %s for %s", k.KeyType, k.KeyID)
	}
	switch k.PublicKeyUse {
	case "sig":
	case "":
		return fmt.Errorf("key usage is empty for %s", k.KeyID)
	default:
		return fmt.Errorf("unsupported key usage %s for %s", k.PublicKeyUse, k.KeyID)
	}

	if k.Exponent == "" {
		return fmt.Errorf("key exponent is empty for %s", k.KeyID)
	}

	if k.Modulus == "" {
		return fmt.Errorf("key modulus is empty for %s", k.KeyID)
	}

	// Add padding
	if i := len(k.Modulus) % 4; i != 0 {
		k.Modulus += strings.Repeat("=", 4-i)
	}

	var mod []byte
	var err error
	if strings.ContainsAny(k.Modulus, "/+") {
		// This decoding works with + and / signs. (legacy)
		mod, err = base64.StdEncoding.DecodeString(k.Modulus)
	} else {
		// This decoding works with - and _ signs.
		mod, err = base64.URLEncoding.DecodeString(k.Modulus)
	}

	if err != nil {
		return fmt.Errorf("failed to decode key modulus for %s, modulus: %s, error: %s", k.KeyID, k.Modulus, err)
	}
	n := big.NewInt(0)
	n.SetBytes(mod)

	exp, err := base64.StdEncoding.DecodeString(k.Exponent)
	if err != nil {
		return fmt.Errorf("failed to decode key exponent for %s: %s", k.KeyID, err)
	}
	// The "e" (exponent) parameter contains the exponent value for the RSA
	// public key.  It is represented as a Base64urlUInt-encoded value.
	//
	// For instance, when representing the value 65537, the octet sequence
	// to be base64url-encoded MUST consist of the three octets [1, 0, 1];
	// the resulting representation for this value is "AQAB".
	var eb []byte
	if len(exp) < 8 {
		eb = make([]byte, 8-len(exp), 8)
		eb = append(eb, exp...)
	} else {
		eb = exp
	}
	er := bytes.NewReader(eb)
	var e uint64
	if err := binary.Read(er, binary.BigEndian, &e); err != nil {
		return fmt.Errorf("failed to converting key exponent for %s: %s", k.KeyID, err)
	}
	k.publicKey = &rsa.PublicKey{N: n, E: int(e)}
	return nil
}

// GetPublicKey returns pointer to rsa.PublicKey.
func (k *JwksKey) GetPublicKey() *rsa.PublicKey {
	return k.publicKey
}
