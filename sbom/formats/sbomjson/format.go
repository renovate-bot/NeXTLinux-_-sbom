package sbomjson

import (
	"github.com/nextlinux/sbom/internal"
	"github.com/nextlinux/sbom/sbom/sbom"
)

const ID sbom.FormatID = "sbom-json"

func Format() sbom.Format {
	return sbom.NewFormat(
		internal.JSONSchemaVersion,
		encoder,
		decoder,
		validator,
		ID, "json", "sbom",
	)
}
