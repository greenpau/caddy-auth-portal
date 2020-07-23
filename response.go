package portal

// AuthResponse represents authentication response object.
type AuthResponse struct {
	Error   bool   `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	Token   string `json:"token,omitempty"`
}
