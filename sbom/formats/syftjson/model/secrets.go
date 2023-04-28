package model

import (
	"github.com/nextlinux/sbom/sbom/file"
	"github.com/nextlinux/sbom/sbom/source"
)

type Secrets struct {
	Location source.Coordinates  `json:"location"`
	Secrets  []file.SearchResult `json:"secrets"`
}
