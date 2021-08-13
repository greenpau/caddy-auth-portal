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

package tag

import (
	"fmt"
	"github.com/iancoleman/strcase"
	"reflect"
	"strings"
	"unicode"
)

// Options stores compliance check options.
type Options struct {
	Disabled           bool
	DisableTagPresent  bool
	DisableTagMismatch bool
	DisableTagOnEmpty  bool
}

// GetTagCompliance performs struct tag compliance checks.
func GetTagCompliance(resource interface{}, opts *Options) ([]string, error) {
	var output []string
	if opts == nil {
		opts = &Options{}
	}

	if opts.Disabled {
		return output, nil
	}

	rr := reflect.TypeOf(resource).Elem()
	//resourceType := fmt.Sprintf("%s", rr.Name())
	rk := fmt.Sprintf("%s", rr.Kind())

	if rk != "struct" {
		return nil, fmt.Errorf("resource kind %q is unsupported", rk)
	}

	suggestedStructChanges := []string{}

	requiredTags := []string{"json", "xml", "yaml"}
	for i := 0; i < rr.NumField(); i++ {
		resourceField := rr.Field(i)
		if !unicode.IsUpper(rune(resourceField.Name[0])) {
			// Skip internal fields.
			continue
		}

		expTagValue := convertFieldToTag(resourceField.Name)
		if !opts.DisableTagOnEmpty {
			expTagValue = expTagValue + ",omitempty"
		}
		var lastTag bool
		for j, tagName := range requiredTags {
			if len(requiredTags)-1 == j {
				lastTag = true
			}

			tagValue := resourceField.Tag.Get(tagName)

			if tagValue == "-" {
				continue
			}
			if tagValue == "" && !opts.DisableTagPresent {
				output = append(output, fmt.Sprintf(
					"tag %q not found in %s.%s (%v)",
					tagName,
					//resourceType,
					rr.Name(),
					resourceField.Name,
					resourceField.Type,
				))
				if lastTag {
					tags := makeTags(requiredTags, expTagValue)
					resType := fmt.Sprintf("%v", resourceField.Type)
					resType = strings.Join(strings.Split(resType, ".")[1:], ".")
					suggestedStructChanges = append(suggestedStructChanges, fmt.Sprintf(
						"%s %s %s", resourceField.Name, resType, tags,
					))
				}
				continue
			}
			//if strings.Contains(tagValue, ",omitempty") {
			//	tagValue = strings.Replace(tagValue, ",omitempty", "", -1)
			//}
			if (tagValue != expTagValue) && !opts.DisableTagMismatch {
				output = append(output, fmt.Sprintf(
					"tag %q mismatch found in %s.%s (%v): %s (actual) vs. %s (expected)",
					tagName,
					//resourceType,
					rr.Name(),
					resourceField.Name,
					resourceField.Type,
					tagValue,
					expTagValue,
				))
				continue

			}
		}
	}

	if len(suggestedStructChanges) > 0 {
		output = append(output, fmt.Sprintf(
			"suggested struct changes to %s:\n%s",
			rr.Name(),
			strings.Join(suggestedStructChanges, "\n"),
		))
	}

	if len(output) > 0 {
		return output, fmt.Errorf("struct %q is not compliant", rr.Name())
	}

	return output, nil
}

func convertFieldToTag(s string) string {
	s = strcase.ToSnake(s)
	s = strings.ReplaceAll(s, "_md_5", "_md5")
	s = strings.ReplaceAll(s, "open_ssh", "openssh")
	return s
}

func makeTags(tags []string, s string) string {
	var b strings.Builder
	b.WriteRune('`')
	tagOutput := []string{}
	for _, tag := range tags {
		tagOutput = append(tagOutput, tag+":\""+s+"\"")
	}
	b.WriteString(strings.Join(tagOutput, " "))
	b.WriteRune('`')
	return b.String()
}
