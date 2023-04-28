package text

import (
	"github.com/nextlinux/sbom/sbom/sbom"
)

const ID sbom.FormatID = "sbom-text"

func Format() sbom.Format {
	return sbom.NewFormat(
		sbom.AnyVersion,
		encoder,
		nil,
		nil,
		ID, "text",
	)
}
