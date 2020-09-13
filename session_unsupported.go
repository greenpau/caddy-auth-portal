package portal

import (
	"net/http"
)

// DoRedirectUnsupported redirects to unsupported page.
func (m *AuthPortal) DoRedirectUnsupported(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	return nil
}
