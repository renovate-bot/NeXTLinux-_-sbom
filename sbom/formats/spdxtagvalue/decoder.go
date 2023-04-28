package spdxtagvalue

import (
	"fmt"
	"io"

	"github.com/spdx/tools-golang/tagvalue"

	"github.com/nextlinux/sbom/sbom/formats/common/spdxhelpers"
	"github.com/nextlinux/sbom/sbom/sbom"
)

func decoder(reader io.Reader) (*sbom.SBOM, error) {
	doc, err := tagvalue.Read(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to decode spdx-tag-value: %w", err)
	}

	return spdxhelpers.TosbomModel(doc)
}
