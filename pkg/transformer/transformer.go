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

package transformer

import (
	"context"
	"fmt"
	"github.com/greenpau/caddy-authorize/pkg/acl"
	cfgutils "github.com/greenpau/caddy-authorize/pkg/utils/cfg"
	"strings"
)

// Config represents a common set of configuration settings
// applicable to the cookies issued by authn.Authenticator.
type Config struct {
	Matchers []string `json:"matchers,omitempty" xml:"matchers,omitempty" yaml:"matchers,omitempty"`
	Actions  []string `json:"actions,omitempty" xml:"actions,omitempty" yaml:"actions,omitempty"`
}

type transform struct {
	matcher *acl.AccessList
	actions [][]string
}

// Factory holds configuration and associated finctions
// for the cookies issued by authn.Authenticator.
type Factory struct {
	configs    []*Config
	transforms []*transform
}

// NewFactory returns an instance of cookie factory.
func NewFactory(cfgs []*Config) (*Factory, error) {
	f := &Factory{}
	if len(cfgs) == 0 {
		return nil, fmt.Errorf("transformer has no config")
	}
	f.configs = cfgs

	for _, cfg := range cfgs {
		if len(cfg.Matchers) < 1 {
			return nil, fmt.Errorf("transformer has no matchers: %v", cfg)
		}
		if len(cfg.Actions) < 1 {
			return nil, fmt.Errorf("transformer has no actions: %v", cfg)
		}

		var actions [][]string
		for _, encodedArgs := range cfg.Actions {
			args, err := cfgutils.DecodeArgs(encodedArgs)
			if err != nil {
				return nil, fmt.Errorf("transformer for %q erred during arg decoding: %v", encodedArgs, err)
			}
			switch args[0] {
			case "require":
				actions = append(actions, args)
			case "block", "deny":
				actions = append(actions, args)
			case "ui":
				if len(args) < 4 {
					return nil, fmt.Errorf("transformer for %q erred: ui config too short", encodedArgs)
				}
				switch args[1] {
				case "link":
					actions = append(actions, args[1:])
				default:
					return nil, fmt.Errorf("transformer for %q erred: invalid ui config", encodedArgs)
				}
			case "add", "overwrite":
				if len(args) < 3 {
					return nil, fmt.Errorf("transformer for %q erred: invalid add/overwrite config", encodedArgs)
				}
				actions = append(actions, args)
			case "delete":
				if len(args) < 2 {
					return nil, fmt.Errorf("transformer for %q erred: invalid delete config", encodedArgs)
				}
				actions = append(actions, args)
			case "action":
				if len(args) < 3 {
					return nil, fmt.Errorf("transformer for %q erred: action config too short", encodedArgs)
				}
				switch args[1] {
				case "add", "overwrite", "delete":
				default:
					return nil, fmt.Errorf("transformer for %q erred: invalid action config", encodedArgs)
				}
				actions = append(actions, args[1:])
			default:
				return nil, fmt.Errorf("transformer has unsupported action: %v", args)
			}
		}
		matcher := acl.NewAccessList()
		matchRuleConfigs := []*acl.RuleConfiguration{
			{
				Conditions: cfg.Matchers,
				Action:     "allow",
			},
		}
		if err := matcher.AddRules(context.Background(), matchRuleConfigs); err != nil {
			return nil, err
		}
		tr := &transform{
			matcher: matcher,
			actions: actions,
		}
		f.transforms = append(f.transforms, tr)
	}
	return f, nil
}

// Transform performs user data transformation.
func (f *Factory) Transform(m map[string]interface{}) error {
	var challenges, frontendLinks []string
	for _, transform := range f.transforms {
		if matched := transform.matcher.Allow(context.Background(), m); !matched {
			continue
		}
		for _, args := range transform.actions {
			switch args[0] {
			case "block", "deny":
				return fmt.Errorf("transformer action is block/deny")
			case "require":
				challenges = append(challenges, cfgutils.EncodeArgs(args[1:]))
			case "link":
				frontendLinks = append(frontendLinks, cfgutils.EncodeArgs(args[1:]))
			default:
				if err := transformData(args, m); err != nil {
					return fmt.Errorf("transformer for %v erred: %v", args, err)
				}
			}
		}
	}
	if len(challenges) > 0 {
		m["challenges"] = challenges
	}
	if len(frontendLinks) > 0 {
		m["frontend_links"] = frontendLinks
	}
	return nil
}

func transformData(args []string, m map[string]interface{}) error {
	if len(args) < 3 {
		return fmt.Errorf("too short")
	}
	switch args[0] {
	case "add", "delete", "overwrite":
	default:
		return fmt.Errorf("unsupported action %v", args[0])
	}

	k, dt := acl.GetFieldDataType(args[1])
	switch args[0] {
	case "add":
		switch dt {
		case "list_str":
			var entries, newEntries []string
			switch val := m[k].(type) {
			case string:
				entries = strings.Split(val, " ")
			case []string:
				entries = val
			case []interface{}:
				for _, entry := range val {
					switch e := entry.(type) {
					case string:
						entries = append(entries, e)
					}
				}
			case nil:
			default:
				return fmt.Errorf("unsupported %q field type %T with value: %v in %v", k, val, val, args)
			}
			entries = append(entries, args[2:]...)
			entryMap := make(map[string]bool)
			for _, e := range entries {
				e = strings.TrimSpace(e)
				if e == "" {
					continue
				}
				if _, exists := entryMap[e]; exists {
					continue
				}
				entryMap[e] = true
				newEntries = append(newEntries, e)
			}
			m[k] = newEntries
		case "str":
			switch val := m[k].(type) {
			case string:
				m[k] = val + " " + strings.Join(args[2:], " ")
			case nil:
				m[k] = strings.Join(args[2:], " ")
			}
		default:
			// Handle custom fields.
			v, err := parseCustomFieldValues(args[2:])
			if err != nil {
				return fmt.Errorf("failed transforming %q field for %q action in %v: %v", k, args[0], args, err)
			}
			m[args[1]] = v
			// return fmt.Errorf("unsupported %q field for %q action in %v", k, args[0], args)
		}
	case "overwrite":
		switch dt {
		case "list_str":
			m[k] = append([]string{}, args[2:]...)
		case "str":
			m[k] = strings.Join(args[2:], " ")
		default:
			return fmt.Errorf("unsupported %q field for %q action in %v", k, args[0], args)
		}
	default:
		return fmt.Errorf("unsupported %q action in %v", args[0], args)
	}
	return nil
}

func parseCustomFieldValues(args []string) (interface{}, error) {
	var x int
	for i, arg := range args {
		if arg == "as" {
			x = i
			break
		}
	}
	if x == 0 {
		return nil, fmt.Errorf("as type directive not found")
	}
	if len(args[x:]) < 2 {
		return nil, fmt.Errorf("as type directive is too short")
	}
	dt := strings.Join(args[x+1:], "_")
	switch dt {
	case "string_list", "list":
		return args[:x], nil
	case "string":
		return args[x-1], nil
	}
	return nil, fmt.Errorf("unsupported %q data type", dt)
}
