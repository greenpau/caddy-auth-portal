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

package tests

import (
	"github.com/greenpau/go-identity"
	"github.com/greenpau/go-identity/pkg/requests"
	"path/filepath"
)

var (
	// TestUser1 is the username for user1.
	TestUser1 = "jsmith"
	// TestEmail1 is the email for user1.
	TestEmail1 = "jsmith@gmail.com"
	// TestPwd1 is the password for user1.
	TestPwd1 = NewRandomString(12)
	// TestFullName1 is the full name for user1.
	TestFullName1 = "Smith, John"
	// TestRoles1 is the roles for user1.
	TestRoles1 = []string{"viewer", "editor", "admin", "authp/admin"}
	// TestUser2 is the username for user2.
	TestUser2 = "bjones"
	// TestEmail2 is the email for user2.
	TestEmail2 = "bjones@gmail.com"
	// TestPwd2 is the password for user2.
	TestPwd2 = NewRandomString(16)
	// TestFullName2  is the full name for user2.
	TestFullName2 = ""
	// TestRoles2 is the roles for user2.
	TestRoles2 = []string{"viewer"}
)

// CreateTestDatabase returns database instance.
func CreateTestDatabase(s string) (*identity.Database, error) {
	tmpDir, err := TempDir(s)
	if err != nil {
		return nil, err
	}
	reqs := []*requests.Request{
		{
			User: requests.User{
				Username: TestUser1,
				Password: TestPwd1,
				Email:    TestEmail1,
				FullName: TestFullName1,
				Roles:    TestRoles1,
			},
		},
		{
			User: requests.User{
				Username: TestUser2,
				Password: TestPwd2,
				Email:    TestEmail2,
				FullName: TestFullName2,
				Roles:    TestRoles2,
			},
		},
	}

	db, err := identity.NewDatabase(filepath.Join(tmpDir, "user_db.json"))
	if err != nil {
		return nil, err
	}

	for _, req := range reqs {
		if err := db.AddUser(req); err != nil {
			return nil, err
		}
	}
	return db, nil
}
