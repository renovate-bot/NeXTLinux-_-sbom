package cpp

import (
	"testing"

	"github.com/nextlinux/sbom/sbom/pkg/cataloger/internal/pkgtest"
)

func TestCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain conan files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"somewhere/src/conanfile.txt",
				"somewhere/src/conan.lock",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewConanCataloger())
		})
	}
}
