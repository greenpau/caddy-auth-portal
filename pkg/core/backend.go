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

package core

import (
	"fmt"

	"github.com/greenpau/caddy-auth-portal/pkg/backends"
)

// GetBackend returns the pointer to the backend specified in the request.
func (p *AuthPortal) GetBackend(r map[string]interface{}) (*backends.Backend, error) {
	if len(p.Backends) < 1 {
		return nil, fmt.Errorf("no backends found")
	}
	for _, k := range []string{"backend_method", "backend_name", "backend_realm"} {
		if _, exists := r[k]; !exists {
			return nil, fmt.Errorf("%s not found", k)
		}
		v := r[k]
		switch v.(type) {
		case string:
		default:
			return nil, fmt.Errorf("%s is not a string", k)
		}
	}

	for _, backend := range p.Backends {
		if backend.GetRealm() != r["backend_realm"].(string) {
			continue
		}
		if backend.GetName() != r["backend_name"].(string) {
			continue
		}
		if backend.GetMethod() != r["backend_method"].(string) {
			continue
		}
		return &backend, nil
	}
	return nil, fmt.Errorf("no matching backend found")
}
