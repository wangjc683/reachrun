// Command reachrun contains the temporary Phase 0 diagnostic CLI. The V1 user
// entry point will become the local browser application in a later phase.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
	"github.com/wangjc683/reachrun/internal/probe"
)

const phase0ResolveTimeout = 5 * time.Second

func main() {
	os.Exit(mainExitCode())
}

func mainExitCode() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	return run(ctx, os.Args[1:], os.Stdout, os.Stderr, systemresolver.New())
}

func run(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	resolver systemresolver.Resolver,
) int {
	if len(args) != 2 || args[0] != "resolve" {
		printUsage(stderr)
		return 2
	}

	resolveContext, cancel := context.WithTimeout(ctx, phase0ResolveTimeout)
	defer cancel()

	result := resolver.Resolve(resolveContext, args[1])
	if err := systemresolver.Validate(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: invalid system resolver result: %v\n", err)
		return 1
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: encode result: %v\n", err)
		return 1
	}

	switch result.Outcome {
	case probe.OutcomeSucceeded:
		return 0
	case probe.OutcomeCancelled:
		return 130
	default:
		return 1
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage: reachrun resolve <hostname>")
	fmt.Fprintln(output, "Phase 0 diagnostic: print one system-resolution evidence envelope as JSON.")
}
