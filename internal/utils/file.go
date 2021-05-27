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
	"io/ioutil"
	"os"
	"path/filepath"
)

func expandHomePath(fp string) (string, error) {
	if fp[0] != '~' {
		return fp, nil
	}
	hd, err := os.UserHomeDir()
	if err != nil {
		return fp, err
	}
	fp = filepath.Join(hd, fp[1:])
	return fp, nil
}

// ReadFileBytes expands home directory and reads a file.
func ReadFileBytes(fp string) ([]byte, error) {
	var err error
	fp, err = expandHomePath(fp)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadFile(fp)
}
