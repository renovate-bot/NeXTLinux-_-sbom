package swift

import (
	"github.com/nextlinux/packageurl-go"
	"github.com/nextlinux/sbom/sbom/pkg"
	"github.com/nextlinux/sbom/sbom/source"
)

func newPackage(name, version, hash string, locations ...source.Location) pkg.Package {
	p := pkg.Package{
		Name:         name,
		Version:      version,
		PURL:         packageURL(name, version),
		Locations:    source.NewLocationSet(locations...),
		Type:         pkg.CocoapodsPkg,
		Language:     pkg.Swift,
		MetadataType: pkg.CocoapodsMetadataType,
		Metadata: pkg.CocoapodsMetadata{
			Checksum: hash,
		},
	}

	p.SetID()

	return p
}

func packageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeCocoapods,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
