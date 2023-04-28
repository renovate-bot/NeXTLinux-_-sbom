package generic

import (
	"github.com/nextlinux/sbom/sbom/artifact"
	"github.com/nextlinux/sbom/sbom/linux"
	"github.com/nextlinux/sbom/sbom/pkg"
	"github.com/nextlinux/sbom/sbom/source"
)

type Environment struct {
	LinuxRelease *linux.Release
}

type Parser func(source.FileResolver, *Environment, source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error)
