package handlers

import (
	"github.com/skip2/go-qrcode"
	"go.uber.org/zap"
	"net/http"
)

// ServeBarcodeImage returns barcode image.
func ServeBarcodeImage(w http.ResponseWriter, r *http.Request, opts map[string]interface{}) error {
	authURLPath := opts["auth_url_path"].(string)
	if !opts["authenticated"].(bool) {
		w.Header().Set("Location", authURLPath+"?redirect_url="+r.RequestURI)
		w.WriteHeader(302)
		return nil
	}
	reqID := opts["request_id"].(string)
	log := opts["logger"].(*zap.Logger)
	code := opts["barcode"].(string)

	var png []byte
	png, err := qrcode.Encode(code, qrcode.Medium, 256)
	if err != nil {
		log.Error("Failed encoding QR code", zap.String("request_id", reqID), zap.String("error", err.Error()))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return err
	}

	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
	return nil
}
