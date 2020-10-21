package ui

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
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
