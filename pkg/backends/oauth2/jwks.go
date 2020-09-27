package oauth2

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
}
