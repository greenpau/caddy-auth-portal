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

package handlers

import (
	"encoding/base64"
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
	code := opts["code_uri_encoded"].(string)
	codeURI, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		log.Error("Failed decoding QR URI", zap.String("request_id", reqID), zap.String("error", err.Error()))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte(`Internal Server Error`))
		return err
	}

	var png []byte
	png, err = qrcode.Encode(string(codeURI), qrcode.Medium, 256)
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
