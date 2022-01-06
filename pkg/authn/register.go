// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authn

import (
	"fmt"
	"github.com/greenpau/caddy-auth-portal/pkg/errors"
	"github.com/greenpau/caddy-authorize/pkg/shared/idp"
	"go.uber.org/zap"
)

// Register registers authentication provider instance with the pool.
func (mgr *InstanceManager) Register(m *Authenticator) error {
	var primaryInstance *Authenticator
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if m.Context == "" {
		m.Context = "default"
	}
	if m.Name == "" {
		counter := mgr.incrementMemberCount(m.Context)
		m.Name = fmt.Sprintf("portal-%s-%06d", m.Context, counter)
	}

	status := mgr.getInstanceStatus(m)
	switch status {
	case DelaySecondary:
		m.logger.Debug("DelaySecondary instance registration", zap.String("instance_name", m.Name))
		mgr.backlog[m.Name] = m.Context
		mgr.Members[m.Name] = m
		return nil
	case DuplicatePrimary:
		return errors.ErrTooManyPrimaryInstances.WithArgs(m.Context)
	case BootstrapPrimary:
		m.logger.Debug("Primary instance registration", zap.String("instance_name", m.Name))
		mgr.PrimaryInstances[m.Context] = m
		mgr.Members[m.Name] = m
		if err := idp.Catalog.Register(m.Context, m); err != nil {
			return err
		}
	default:
		// This is BootstrapSecondary.
		m.logger.Debug("Non-primary instance registration", zap.String("instance_name", m.Name))
		primaryInstance = mgr.PrimaryInstances[m.Context]
	}
	return mgr.configure(primaryInstance, m)
}
