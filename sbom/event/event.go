/*
Package event provides event types for all events that the sbom library published onto the event bus. By convention, for each event
defined here there should be a corresponding event parser defined in the parsers/ child package.
*/
package event

import "github.com/wagoodman/go-partybus"

const (
	// AppUpdateAvailable is a partybus event that occurs when an application update is available
	AppUpdateAvailable partybus.EventType = "sbom-app-update-available"

	// PackageCatalogerStarted is a partybus event that occurs when the package cataloging has begun
	PackageCatalogerStarted partybus.EventType = "sbom-package-cataloger-started-event"

	//nolint:gosec
	// SecretsCatalogerStarted is a partybus event that occurs when the secrets cataloging has begun
	SecretsCatalogerStarted partybus.EventType = "sbom-secrets-cataloger-started-event"

	// FileMetadataCatalogerStarted is a partybus event that occurs when the file metadata cataloging has begun
	FileMetadataCatalogerStarted partybus.EventType = "sbom-file-metadata-cataloger-started-event"

	// FileDigestsCatalogerStarted is a partybus event that occurs when the file digests cataloging has begun
	FileDigestsCatalogerStarted partybus.EventType = "sbom-file-digests-cataloger-started-event"

	// FileIndexingStarted is a partybus event that occurs when the directory resolver begins indexing a filesystem
	FileIndexingStarted partybus.EventType = "sbom-file-indexing-started-event"

	// Exit is a partybus event that occurs when an analysis result is ready for final presentation
	Exit partybus.EventType = "sbom-exit-event"

	// ImportStarted is a partybus event that occurs when an SBOM upload process has begun
	ImportStarted partybus.EventType = "sbom-import-started-event"

	// AttestationStarted is a partybus event that occurs when starting an SBOM attestation process
	AttestationStarted partybus.EventType = "sbom-attestation-started-event"

	// CatalogerTaskStarted is a partybus event that occurs when starting a task within a cataloger
	CatalogerTaskStarted partybus.EventType = "sbom-cataloger-task-started"
)
