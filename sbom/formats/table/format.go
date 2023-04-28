package table

import (
	"github.com/nextlinux/sbom/sbom/sbom"
)

const ID sbom.FormatID = "sbom-table"

func Format() sbom.Format {
	return sbom.NewFormat(
		sbom.AnyVersion,
		encoder,
		nil,
		nil,
		ID, "table",
	)
}
