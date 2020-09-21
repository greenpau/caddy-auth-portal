package handlers

import (
	// "encoding/json"
	"github.com/greenpau/caddy-auth-jwt"
	"github.com/greenpau/caddy-auth-portal/pkg/ui"
	"github.com/greenpau/caddy-auth-portal/pkg/utils"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

// ServeSettings returns authenticated user information.
func ServeSettings(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	var codeURI string
	var codeErr error
	authURLPath := opts["auth_url_path"].(string)
	if !opts["authenticated"].(bool) {
		w.Header().Set("Location", authURLPath+"?redirect_url="+r.RequestURI)
		w.WriteHeader(302)
		return nil
	}
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	claims := opts["user_claims"].(*jwt.UserClaims)
	uiFactory := opts["ui"].(*ui.UserInterfaceFactory)
	view := strings.TrimPrefix(r.URL.Path, authURLPath)
	view = strings.TrimPrefix(view, "/settings")
	view = strings.TrimPrefix(view, "/")
	viewParts := strings.Split(view, "/")
	view = viewParts[0]
	if view == "" {
		view = "general"
	}

	switch view {
	case "mfa":
		if len(viewParts) > 1 {
			if viewParts[1] == "barcode" || viewParts[1] == "add" {
				codeOpts := make(map[string]interface{})
				codeOpts["type"] = "totp"
				codeOpts["label"] = claims.Email
				codeOpts["secret"] = "My@Secret!"
				codeOpts["period"] = 30
				codeOpts["issuer"] = "Gatekeeper"
				// codeOpts["algorithm"] = "SHA512"
				// codeOpts["digits"] = 8
				codeURI, codeErr = utils.GetCodeURI(codeOpts)
				if codeErr != nil {
					log.Error("Failed creating key code URI", zap.String("request_id", reqID), zap.String("error", codeErr.Error()))
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(500)
					w.Write([]byte(`Internal Server Error`))
					return codeErr
				}
			}
			switch viewParts[1] {
			case "barcode":
				opts["barcode"] = codeURI
				return ServeBarcodeImage(w, r, opts)
			case "add":
				opts["barcode"] = codeURI
				view = strings.Join(viewParts, "-")
			}
		}
	}

	// claims := opts["user_claims"].(*jwt.UserClaims)

	// Display main authentication portal page
	resp := uiFactory.GetArgs()
	resp.Title = "Settings"
	resp.Data["view"] = view

	content, err := uiFactory.Render("settings", resp)
	if err != nil {
		log.Error("Failed HTML response rendering", zap.String("request_id", reqID), zap.String("error", err.Error()))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return err
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write(content.Bytes())
	return nil
}
