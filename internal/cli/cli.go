// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package cli provides the PCCS command line interface.
package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/toratako/pccs-go/internal/config"
)

// Version can be set at build time with -ldflags '-X .../internal/cli.Version=...'.
var Version = "development"

const help = `Usage: pccs COMMAND [OPTIONS]

Commands:
  init                 Create configuration, localhost TLS certificate, and tokens
  serve                Run the PCCS HTTPS service
  config check         Validate configuration and environment overrides
  token generate       Print a new random token
  token hash           Print the SHA-512 hash of a token read from stdin
  health               Query server readiness
  platforms list       Fetch platforms (reg/reg_na drains the registration queue)
  platforms register   Register platforms from a JSON file or stdin
  collateral import    Import collateral from a JSON file or stdin
  refresh              Refresh cached collateral or selected platform certificates
  version              Print the version

Run pccs COMMAND --help for options. Configuration defaults to
PCCS_CONFIG or pccs/config.json. Secrets are read from PCCS_ADMIN_TOKEN /
PCCS_USER_TOKEN or admin.token / user.token beside the configuration file.

Examples:
  pccs init --dir pccs
  pccs serve --config pccs/config.json
  pccs platforms list --source '[]'
  pccs platforms register --file platforms.json
  pccs collateral import --file collateral.json
`

// Run executes a command. Results and help go to stdout; diagnostics go to stderr.
// Callers determine the process exit status from the returned error.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		if len(args) > 1 {
			return errors.New("help takes no arguments; use COMMAND --help")
		}
		_, err := io.WriteString(stdout, help)
		return err
	}
	switch args[0] {
	case "version":
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			_, err := fmt.Fprintln(stdout, "Usage: pccs version\n\nPrint the version.")
			return err
		}
		if len(args) != 1 {
			return errors.New("version takes no arguments")
		}
		_, err := fmt.Fprintln(stdout, Version)
		return err
	case "init":
		fs := flags("init", "Create a private directory with config.json, ca.crt, server.crt, server.key,\nadmin.token, and user.token. Existing directories are not overwritten.", stdout)
		dir := fs.String("dir", "pccs", "directory to initialize")
		if done, err := parse(fs, args[1:]); done {
			return err
		}
		path, err := config.Initialize(*dir)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, path)
		return err
	case "config":
		if len(args) < 2 || args[1] != "check" {
			if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
				_, err := fmt.Fprintln(stdout, "Usage: pccs config check [--config PATH]")
				return err
			}
			return errors.New("usage: pccs config check [--config PATH]")
		}
		fs := flags("config check", "Validate JSON configuration and PCCS_* environment overrides.", stdout)
		path := fs.String("config", defaultConfigPath(), "configuration JSON file")
		if done, err := parse(fs, args[2:]); done {
			return err
		}
		if _, err := config.Load(*path); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "Configuration is valid.")
		return err
	case "token":
		return runToken(args[1:], stdin, stdout)
	case "serve":
		return runServe(ctx, args[1:], stdout, stderr)
	case "health", "platforms", "collateral", "refresh":
		return runClient(ctx, args, stdin, stdout)
	default:
		return errors.New("unknown command; run pccs --help")
	}
}

func flags(command, description string, stdout io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {
		fmt.Fprintf(stdout, "Usage: pccs %s [OPTIONS]\n\n%s\n\nOptions:\n", command, description)
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		fs.SetOutput(io.Discard)
		fmt.Fprintln(stdout, "  -h, --help\n        show help")
	}
	return fs
}

func parse(fs *flag.FlagSet, args []string) (bool, error) {
	usage := fs.Usage
	fs.Usage = func() {}
	err := fs.Parse(args)
	fs.Usage = usage
	if errors.Is(err, flag.ErrHelp) {
		usage()
		return true, nil
	}
	if err != nil {
		return true, err
	}
	if fs.NArg() != 0 {
		return true, errors.New("unexpected positional arguments; use --help")
	}
	return false, nil
}

func defaultConfigPath() string {
	if value := os.Getenv("PCCS_CONFIG"); value != "" {
		return value
	}
	return "pccs/config.json"
}

func runToken(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 2 && (args[0] == "generate" || args[0] == "hash") && (args[1] == "--help" || args[1] == "-h") {
		args = []string{"--help"}
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		_, err := fmt.Fprintln(stdout, "Usage: pccs token generate\n       pccs token hash < TOKEN_FILE\n\nToken hashes use SHA-512. Token input is limited to 4096 bytes.")
		return err
	}
	if len(args) != 1 {
		return errors.New("usage: pccs token generate | pccs token hash < TOKEN_FILE")
	}
	switch args[0] {
	case "generate":
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return errors.New("could not generate token")
		}
		_, err := fmt.Fprintln(stdout, base64.RawURLEncoding.EncodeToString(buf))
		return err
	case "hash":
		data, err := io.ReadAll(io.LimitReader(stdin, 4097))
		if err != nil {
			return errors.New("could not read token from stdin")
		}
		if len(data) > 4096 {
			return errors.New("token input exceeds 4096 bytes")
		}
		token, err := cleanToken(string(data))
		if err != nil {
			return err
		}
		sum := sha512.Sum512([]byte(token))
		_, err = fmt.Fprintln(stdout, hex.EncodeToString(sum[:]))
		return err
	default:
		return errors.New("unknown token command; use pccs token --help")
	}
}

func cleanToken(value string) (string, error) {
	value = strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r")
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("token must contain one nonempty line of at most 4096 bytes")
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return "", errors.New("token must contain printable ASCII without spaces")
		}
	}
	return value, nil
}
