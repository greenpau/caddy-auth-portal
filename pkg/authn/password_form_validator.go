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

package authn

import (
	"fmt"
	"github.com/greenpau/go-identity/pkg/requests"
	"net/http"
)

func validatePasswordChangeForm(r *http.Request, rr *requests.Request) error {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return fmt.Errorf("Unsupported content type")
	}
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("Failed parsing submitted form")
	}
	for _, k := range []string{"secret1", "secret2", "secret3"} {
		if r.PostFormValue(k) == "" {
			return fmt.Errorf("Required form field not found")
		}
	}
	if r.PostFormValue("secret1") == "" {
		return fmt.Errorf("Current password is empty")
	}
	if r.PostFormValue("secret2") == "" {
		return fmt.Errorf("New password is empty")
	}
	if r.PostFormValue("secret2") != r.PostFormValue("secret3") {
		return fmt.Errorf("New password mismatch")
	}
	if r.PostFormValue("secret1") == r.PostFormValue("secret2") {
		return fmt.Errorf("New password matches current password")
	}
	rr.User.OldPassword = r.PostFormValue("secret1")
	rr.User.Password = r.PostFormValue("secret2")
	return nil
}
