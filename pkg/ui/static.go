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

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
)

// StaticAssets is an instance of StaticAssetLibrary.
var StaticAssets *StaticAssetLibrary

// StaticAsset is a single static web asset.
type StaticAsset struct {
	Path           string
	Restricted     bool
	ContentType    string
	Content        string
	EncodedContent string
	Checksum       string
}

// StaticAssetLibrary contains a collection of static assets.
type StaticAssetLibrary struct {
	items map[string]*StaticAsset
}

func init() {
	var err error
	StaticAssets, err = NewStaticAssetLibrary()
	if err != nil {
		panic(err)
	}
}

// NewStaticAssetLibrary returns an instance of StaticAssetLibrary.
func NewStaticAssetLibrary() (*StaticAssetLibrary, error) {
	sal := &StaticAssetLibrary{}
	sal.items = make(map[string]*StaticAsset)
	for path, item := range defaultStaticAssets {
		s, err := base64.StdEncoding.DecodeString(item.EncodedContent)
		if err != nil {
			return nil, fmt.Errorf("static asset %s decoding error: %s", path, err)
		}
		item.Content = string(s)
		h := sha1.New()
		io.WriteString(h, item.Content)
		item.Checksum = base64.URLEncoding.EncodeToString(h.Sum(nil))
		sal.items[path] = item
	}
	return sal, nil
}

// GetAsset returns an asset from path
func (sal *StaticAssetLibrary) GetAsset(path string) (*StaticAsset, error) {
	if item, exists := sal.items[path]; exists {
		return item, nil
	}
	return nil, fmt.Errorf("static asset %s not found", path)
}

// AddAsset adds asset to StaticAssetLibrary
func (sal *StaticAssetLibrary) AddAsset(path, contentType, fsPath string) error {
	rawContent, err := ioutil.ReadFile(fsPath)
	if err != nil {
		return fmt.Errorf("failed to load asset file %s: %s", fsPath, err)
	}
	item := &StaticAsset{
		Path:           path,
		ContentType:    contentType,
		EncodedContent: base64.StdEncoding.EncodeToString(rawContent),
	}
	s, err := base64.StdEncoding.DecodeString(item.EncodedContent)
	if err != nil {
		return fmt.Errorf("static asset %s decoding error: %s", path, err)
	}
	item.Content = string(s)
	h := sha1.New()
	io.WriteString(h, item.Content)
	item.Checksum = base64.URLEncoding.EncodeToString(h.Sum(nil))
	sal.items[path] = item
	return nil
}
