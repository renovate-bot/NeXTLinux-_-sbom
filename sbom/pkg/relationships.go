package pkg

import "github.com/nextlinux/sbom/sbom/artifact"

func NewRelationships(catalog *Collection) []artifact.Relationship {
	rels := RelationshipsByFileOwnership(catalog)
	rels = append(rels, RelationshipsEvidentBy(catalog)...)
	return rels
}
