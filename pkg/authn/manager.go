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
	"sync"
)

// InstanceStatus is the state of an Instance.
type InstanceStatus int

const (
	// Unknown is indeterminate state.
	Unknown InstanceStatus = iota
	// BootstrapPrimary is primary instance is ready for bootstrapping.
	BootstrapPrimary
	// BootstrapSecondary is non-primary instance is ready for bootstrapping.
	BootstrapSecondary
	// DelaySecondary is non-primary instance is not ready for bootstrapping.
	DelaySecondary
	// DuplicatePrimary is a dumplicate primary instance.
	DuplicatePrimary
)

// InstanceManager provides access to all Authenticator instances.
type InstanceManager struct {
	mu               sync.Mutex
	Members          map[string]*Authenticator
	PrimaryInstances map[string]*Authenticator
	MemberCount      map[string]int
	backlog          map[string]string
}

// AuthManager is the global authentication provider pool.
var AuthManager *InstanceManager

func init() {
	AuthManager = NewInstanceManager()
}

// NewInstanceManager returns a new instance of InstanceManager.
func NewInstanceManager() *InstanceManager {
	mgr := &InstanceManager{
		Members:          make(map[string]*Authenticator),
		PrimaryInstances: make(map[string]*Authenticator),
		MemberCount:      make(map[string]int),
		backlog:          make(map[string]string),
	}
	return mgr
}

func (mgr *InstanceManager) incrementMemberCount(ctxName string) int {
	if _, exists := mgr.MemberCount[ctxName]; exists {
		mgr.MemberCount[ctxName]++
	} else {
		mgr.MemberCount[ctxName] = 1
	}
	return mgr.MemberCount[ctxName]
}

func (mgr *InstanceManager) getInstanceStatus(m *Authenticator) InstanceStatus {
	primary, primaryFound := mgr.PrimaryInstances[m.Context]
	if !primaryFound {
		// Initial startup with no primary instance.
		if m.PrimaryInstance {
			return BootstrapPrimary
		}
		return DelaySecondary
	}
	timeDiff := m.startedAt.Sub(primary.startedAt).Milliseconds()
	if timeDiff > 1000 {
		// Reload
		if m.PrimaryInstance {
			return BootstrapPrimary
		}
		return DelaySecondary
	}
	if m.PrimaryInstance {
		// Initial startup and likely multiple primary instances.
		return DuplicatePrimary
	}
	return BootstrapSecondary
}
