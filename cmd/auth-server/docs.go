package main

import (
	"log/slog"
	"os"

	"github.com/xiant10/t10-modkit/docsmcp"

	repodocs "t10-auth-server/docs"
)

// version is the commit the image was built from, set by the Dockerfile's VERSION.
var version = "dev"

// ownDocs serves this repo's docs to coding agents at /docs/mcp, in front of
// everything else, as the workspace's contracts/docs describes.
var ownDocs *docsmcp.Handler

// loadDocs reads the docs, and serves only them when the command runs as
// "<command> docs <addr>", for the docs contract's suite.
func loadDocs() {
	var err error
	ownDocs, err = docsmcp.New(docsmcp.Options{
		Component: "auth-server",
		Summary:   "t10's only identity issuer: sign-in for web, desktop, mobile and mini-program apps, tokens and JWKS, tenants and members, grants for agents, and business roles.",
		Version:   version,
		Docs:      repodocs.FS,
	})
	if err != nil {
		slog.Error("read docs", "error", err)
		os.Exit(1)
	}
	if served, err := docsmcp.DocsOnly(os.Args, ownDocs); served {
		slog.Error("docs only stopped", "error", err)
		os.Exit(1)
	}
}
