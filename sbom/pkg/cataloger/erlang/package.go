package erlang

import (
	"github.com/nextlinux/packageurl-go"
	"github.com/nextlinux/sbom/sbom/pkg"
	"github.com/nextlinux/sbom/sbom/source"
)

func newPackage(d pkg.RebarLockMetadata, locations ...source.Location) pkg.Package {
	p := pkg.Package{
		Name:         d.Name,
		Version:      d.Version,
		Language:     pkg.Erlang,
		Locations:    source.NewLocationSet(locations...),
		PURL:         packageURL(d),
		Type:         pkg.HexPkg,
		MetadataType: pkg.RebarLockMetadataType,
		Metadata:     d,
	}

	p.SetID()

	return p
}

func packageURL(m pkg.RebarLockMetadata) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeHex,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
