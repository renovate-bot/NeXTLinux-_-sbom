package cyclonedxjson

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/nextlinux/sbom/sbom/formats/common/cyclonedxhelpers"
	"github.com/nextlinux/sbom/sbom/sbom"
)

const ID sbom.FormatID = "cyclonedx-json"

func Format() sbom.Format {
	return sbom.NewFormat(
		sbom.AnyVersion,
		encoder,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatJSON),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatJSON),
		ID,
	)
}
