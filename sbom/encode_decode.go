package sbom

import (
	"io"

	"github.com/nextlinux/sbom/sbom/formats"
	"github.com/nextlinux/sbom/sbom/sbom"
)

// TODO: deprecated, moved to sbom/formats/formats.go. will be removed in v1.0.0
func Encode(s sbom.SBOM, f sbom.Format) ([]byte, error) {
	return formats.Encode(s, f)
}

// TODO: deprecated, moved to sbom/formats/formats.go. will be removed in v1.0.0
func Decode(reader io.Reader) (*sbom.SBOM, sbom.Format, error) {
	return formats.Decode(reader)
}
