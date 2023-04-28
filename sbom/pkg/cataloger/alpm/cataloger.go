package alpm

import (
	"github.com/anchore/sbom/sbom/pkg"
	"github.com/anchore/sbom/sbom/pkg/cataloger/generic"
)

const catalogerName = "alpmdb-cataloger"

func NewAlpmdbCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseAlpmDB, pkg.AlpmDBGlob)
}
