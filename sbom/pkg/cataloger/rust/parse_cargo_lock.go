package rust

import (
	"fmt"

	"github.com/pelletier/go-toml"

	"github.com/anchore/sbom/sbom/artifact"
	"github.com/anchore/sbom/sbom/pkg"
	"github.com/anchore/sbom/sbom/pkg/cataloger/generic"
	"github.com/anchore/sbom/sbom/source"
)

var _ generic.Parser = parseCargoLock

type cargoLockFile struct {
	Packages []pkg.CargoPackageMetadata `toml:"package"`
}

// parseCargoLock is a parser function for Cargo.lock contents, returning all rust cargo crates discovered.
func parseCargoLock(_ source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	tree, err := toml.LoadReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load Cargo.lock for parsing: %w", err)
	}

	m := cargoLockFile{}
	err = tree.Unmarshal(&m)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse Cargo.lock: %w", err)
	}

	var pkgs []pkg.Package

	for _, p := range m.Packages {
		if p.Dependencies == nil {
			p.Dependencies = make([]string, 0)
		}
		pkgs = append(
			pkgs,
			newPackageFromCargoMetadata(
				p,
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	return pkgs, nil, nil
}
