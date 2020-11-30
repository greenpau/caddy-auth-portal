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

package ui

// UserInterfaceLink represents a single HTML link.
type UserInterfaceLink struct {
	Link          string `json:"link,omitempty"`
	Title         string `json:"title,omitempty"`
	Style         string `json:"style,omitempty"`
	OpenNewWindow bool   `json:"open_new_window,omitempty"`
	Target        string `json:"target,omitempty"`
	TargetEnabled bool   `json:"target_enabled,omitempty"`
	IconName      string `json:"icon_name,omitempty"`
	IconEnabled   bool   `json:"icon_enabled,omitempty"`
}
