package generic

import (
	"github.com/anchore/sbom/sbom/artifact"
	"github.com/anchore/sbom/sbom/linux"
	"github.com/anchore/sbom/sbom/pkg"
	"github.com/anchore/sbom/sbom/source"
)

type Environment struct {
	LinuxRelease *linux.Release
}

type Parser func(source.FileResolver, *Environment, source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error)
