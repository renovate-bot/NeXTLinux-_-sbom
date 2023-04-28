package dart

import (
	"github.com/nextlinux/sbom/sbom/pkg/cataloger/generic"
)

const catalogerName = "dartlang-lock-cataloger"

// NewPubspecLockCataloger returns a new Dartlang cataloger object base on pubspec lock files.
func NewPubspecLockCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parsePubspecLock, "**/pubspec.lock")
}
