package sbomjson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/nextlinux/sbom/sbom/formats/sbomjson/model"
	"github.com/nextlinux/sbom/sbom/sbom"
)

func decoder(reader io.Reader) (*sbom.SBOM, error) {
	dec := json.NewDecoder(reader)

	var doc model.Document
	err := dec.Decode(&doc)
	if err != nil {
		return nil, fmt.Errorf("unable to decode sbom-json: %w", err)
	}

	return tosbomModel(doc)
}
