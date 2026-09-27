// update.go implements `toha3ee updates`: check the running version against
// toha3ee's official QYVORA GitHub releases and install a newer release after
// cryptographic verification. See internal/selfupdate for the shared flow.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-toha3ee/internal/selfupdate"
	"github.com/QYVORA/qyvora-toha3ee/internal/session"
)

// releaseConfig pins the updater to toha3ee's official release source: the
// QYVORA/qyvora-toha3ee GitHub repository and nothing else.
func releaseConfig() selfupdate.Config {
	return selfupdate.Config{
		Owner:    "QYVORA",
		Repo:     "qyvora-toha3ee",
		ToolName: "toha3ee",
		CurrentVersion: func() string {
			return session.Version
		},
		ArtifactName: func(goos, goarch string) string {
			// Release assets are bare executables named
			// "{tool}-{os}-{arch}" with a ".exe" suffix on Windows. macOS is
			// published as "macos", never "darwin".
			//
			// This previously resolved to a "toha3ee_{os}_{arch}.tar.gz"
			// archive with a per-artifact ".sha256" sidecar. Both were wrong
			// for the current pipeline: the release ships bare binaries and a
			// single checksums.txt manifest, and a bare-digest sidecar does
			// not match a manifest line of the form "<sha256>  <name>".
			os := goos
			if os == "darwin" {
				os = "macos"
			}
			name := fmt.Sprintf("toha3ee-%s-%s", os, goarch)
			if goos == "windows" {
				name += ".exe"
			}
			return name
		},
		// One manifest for the whole release, not a per-artifact sidecar.
		ChecksumAsset: func(string) string { return "checksums.txt" },
		// The release publishes bare binaries, so nothing is unpacked. The
		// engine's ArchiveFor support is left in place for tools that do ship
		// archives; returning nil here is what disables it for toha3ee.
		ArchiveFor: nil,
	}
}

// newUpdatesCmd builds the `toha3ee updates` command. outFormat points at
// the shared -o/--output flag value owned by the root command wiring.
func newUpdatesCmd(outFormat *string) *cobra.Command {
	return &cobra.Command{
		Use:     "updates",
		Aliases: []string{"update"},
		Short:   "update toha3ee from official QYVORA releases",
		Long: `Check for a newer toha3ee release and install it.

The installed version is compared against the latest official QYVORA
GitHub release for this platform. If an update exists, it is downloaded,
verified against the release SHA-256 checksums, and swapped in atomically;
the previous binary is never touched unless every step succeeds.

No Go toolchain, Git, or source checkout is required.`,
		Args: exactArgsUsage(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := selfupdate.Options{Out: cmd.OutOrStdout()}
			jsonMode := *outFormat == "json" || quiet
			markdownMode := *outFormat == "markdown"
			if jsonMode || markdownMode {
				opts.Quiet = true
			}

			res, err := selfupdate.Run(cmd.Context(), releaseConfig(), opts)
			switch {
			case jsonMode:
				payload := map[string]string{
					"framework": "toha3ee",
					"command":   "updates",
					"installed": res.Current,
					"latest":    res.Latest,
				}
				if err != nil {
					payload["status"] = "failed"
					payload["error"] = err.Error()
					var ue *selfupdate.UpdateError
					if errors.As(err, &ue) {
						payload["kind"] = string(ue.Kind)
					}
				} else {
					payload["status"] = map[selfupdate.Status]string{
						selfupdate.StatusUpdated:        "updated",
						selfupdate.StatusCurrent:        "current",
						selfupdate.StatusNewerInstalled: "newer_installed",
					}[res.Status]
					if res.Status == selfupdate.StatusUpdated {
						payload["path"] = res.Path
					}
				}
				data, jerr := json.MarshalIndent(payload, "", "  ")
				if jerr != nil {
					return jerr
				}
				fmt.Fprintln(os.Stdout, string(data))
			case markdownMode && err == nil:
				status := map[selfupdate.Status]string{
					selfupdate.StatusUpdated:        "updated to **%s**",
					selfupdate.StatusCurrent:        "already up to date (**%s**)",
					selfupdate.StatusNewerInstalled: "**%s** is newer than the latest release; no downgrade performed",
				}[res.Status]
				arg := res.Latest
				if res.Status == selfupdate.StatusNewerInstalled {
					arg = res.Current
				}
				fmt.Fprintf(os.Stdout, "**toha3ee** "+status+"\n", arg)
			}

			return wrapUpdateError(err)
		},
	}
}

// wrapUpdateError keeps failures clean while expanding permission denials
// into actionable multi-line guidance.
func wrapUpdateError(err error) error {
	if err == nil {
		return nil
	}
	var ue *selfupdate.UpdateError
	if !errors.As(err, &ue) {
		return err
	}
	if ue.Kind == selfupdate.KindPermission && ue.Path() != "" {
		return fmt.Errorf("%s\n\n%s", ue.Error(), selfupdate.PermissionHint("toha3ee", ue.Path()))
	}
	return ue
}
