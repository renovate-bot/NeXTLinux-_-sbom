package cli

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nextlinux/sbom/cmd/sbom/cli/convert"
	"github.com/nextlinux/sbom/cmd/sbom/cli/options"
	"github.com/nextlinux/sbom/internal"
	"github.com/nextlinux/sbom/internal/config"
)

const (
	convertExample = `  {{.appName}} {{.command}} img.sbom.json -o spdx-json                      convert a sbom SBOM to spdx-json, output goes to stdout
  {{.appName}} {{.command}} img.sbom.json -o cyclonedx-json=img.cdx.json    convert a sbom SBOM to CycloneDX, output is written to the file "img.cdx.json""
  {{.appName}} {{.command}} - -o spdx-json                                  convert an SBOM from STDIN to spdx-json
`
)

//nolint:dupl
func Convert(v *viper.Viper, app *config.Application, ro *options.RootOptions, po *options.PackagesOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "convert [SOURCE-SBOM] -o [FORMAT]",
		Short: "Convert between SBOM formats",
		Long:  "[Experimental] Convert SBOM files to, and from, SPDX, CycloneDX and Syft's format. For more info about data loss between formats see https://github.com/nextlinux/sbom#format-conversion-experimental",
		Example: internal.Tprintf(convertExample, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "convert",
		}),
		Args: func(cmd *cobra.Command, args []string) error {
			if err := app.LoadAllValues(v, ro.Config); err != nil {
				return fmt.Errorf("invalid application config: %w", err)
			}
			newLogWrapper(app)
			logApplicationConfig(app)
			return validateArgs(cmd, args)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if app.CheckForAppUpdate {
				checkForApplicationUpdate()
			}
			return convert.Run(cmd.Context(), app, args)
		},
	}

	err := po.AddFlags(cmd, v)
	if err != nil {
		log.Fatal(err)
	}

	return cmd
}
