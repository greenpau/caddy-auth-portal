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
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"go.uber.org/zap"
)

// Validate validates the provisioning of an Authenticator instance.
func (mgr *InstanceManager) Validate(m *Authenticator) error {
	if !m.PrimaryInstance {
		if _, primaryFound := mgr.PrimaryInstances[m.Context]; !primaryFound {
			m.logger.Error(
				"Primary instance not found",
				zap.String("instance_name", m.Name),
				zap.String("context", m.Context),
			)
			return errors.ErrInstanceManagerValidate.WithArgs(m.Name, "primary instance not found")
		}
		return nil
	}
	m.logger.Debug("Instance validation", zap.String("instance_name", m.Name))
	for instanceName, ctxName := range mgr.backlog {
		if ctxName != m.Context {
			continue
		}
		instance := mgr.Members[instanceName]
		if err := mgr.Register(instance); err != nil {
			return errors.ErrInstanceManagerValidate.WithArgs(m.Name, err)
		}
		m.logger.Debug("Non-primary instance validated", zap.String("instance_name", instanceName))
	}

	m.logger.Debug("Primary instance validated", zap.String("instance_name", m.Name))
	return nil
}
