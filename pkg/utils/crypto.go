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

package utils

import (
	"bufio"
	"bytes"
	"os"
	"strings"
)

// ReadCertFile return certificate content as a string.
func ReadCertFile(filePath string) (string, error) {
	var buffer bytes.Buffer
	var RecordingEnabled bool
	fileHandle, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer fileHandle.Close()

	scanner := bufio.NewScanner(fileHandle)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "-----") {
			if strings.Contains(line, "BEGIN CERTIFICATE") {
				RecordingEnabled = true
				continue
			}
			if strings.Contains(line, "END CERTIFICATE") {
				break
			}
		}
		if RecordingEnabled {
			buffer.WriteString(strings.TrimSpace(line))
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return buffer.String(), nil
}
