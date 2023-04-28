/*
Package ui provides all public UI elements intended to be repurposed in other applications. Specifically, a single
Handler object is provided to allow consuming applications (such as grype) to check if there are UI elements the handler
can respond to (given a specific event type) and handle the event in context of the given screen frame object.
*/
package ui

import (
	"context"
	"sync"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"

	stereoscopeEvent "github.com/nextlinux/stereoscope/pkg/event"
	sbomEvent "github.com/nextlinux/sbom/sbom/event"
)

// Handler is an aggregated event handler for the set of supported events (PullDockerImage, ReadImage, FetchImage, PackageCatalogerStarted)
type Handler struct {
}

// NewHandler returns an empty Handler
func NewHandler() *Handler {
	return &Handler{}
}

// RespondsTo indicates if the handler is capable of handling the given event.
func (r *Handler) RespondsTo(event partybus.Event) bool {
	switch event.Type {
	case stereoscopeEvent.PullDockerImage,
		stereoscopeEvent.ReadImage,
		stereoscopeEvent.FetchImage,
		sbomEvent.PackageCatalogerStarted,
		sbomEvent.SecretsCatalogerStarted,
		sbomEvent.FileDigestsCatalogerStarted,
		sbomEvent.FileMetadataCatalogerStarted,
		sbomEvent.FileIndexingStarted,
		sbomEvent.ImportStarted,
		sbomEvent.AttestationStarted,
		sbomEvent.CatalogerTaskStarted:
		return true
	default:
		return false
	}
}

// Handle calls the specific event handler for the given event within the context of the screen frame.
func (r *Handler) Handle(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	switch event.Type {
	case stereoscopeEvent.PullDockerImage:
		return PullDockerImageHandler(ctx, fr, event, wg)

	case stereoscopeEvent.ReadImage:
		return ReadImageHandler(ctx, fr, event, wg)

	case stereoscopeEvent.FetchImage:
		return FetchImageHandler(ctx, fr, event, wg)

	case sbomEvent.PackageCatalogerStarted:
		return PackageCatalogerStartedHandler(ctx, fr, event, wg)

	case sbomEvent.SecretsCatalogerStarted:
		return SecretsCatalogerStartedHandler(ctx, fr, event, wg)

	case sbomEvent.FileDigestsCatalogerStarted:
		return FileDigestsCatalogerStartedHandler(ctx, fr, event, wg)

	case sbomEvent.FileMetadataCatalogerStarted:
		return FileMetadataCatalogerStartedHandler(ctx, fr, event, wg)

	case sbomEvent.FileIndexingStarted:
		return FileIndexingStartedHandler(ctx, fr, event, wg)

	case sbomEvent.ImportStarted:
		return ImportStartedHandler(ctx, fr, event, wg)

	case sbomEvent.AttestationStarted:
		return AttestationStartedHandler(ctx, fr, event, wg)

	case sbomEvent.CatalogerTaskStarted:
		return CatalogerTaskStartedHandler(ctx, fr, event, wg)
	}
	return nil
}
