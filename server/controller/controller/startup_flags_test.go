// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControllerStartUsesCallerConfigurationWithoutReparsingFlags(t *testing.T) {
	if os.Getenv("TRAFLENS_CONTROLLER_FLAG_PROBE") == "1" {
		path := os.Getenv("TRAFLENS_CONTROLLER_INVALID_CONFIG")
		// The actual server entry point has already parsed its own -f option.
		// Unrelated process-global flags must not be parsed by this component.
		flag.CommandLine = flag.NewFlagSet("component-probe", flag.ExitOnError)
		os.Args = []string{"component-probe", "-f", path}
		Start(context.Background(), "test", path, "", nil)
		os.Exit(97)
	}
	path := filepath.Join(t.TempDir(), "invalid-controller.yaml")
	if err := os.WriteFile(path, []byte("controller: [\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestControllerStartUsesCallerConfigurationWithoutReparsingFlags$")
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"TRAFLENS_CONTROLLER_FLAG_PROBE=1",
		"TRAFLENS_CONTROLLER_INVALID_CONFIG=" + path,
		"DEEPFLOW_SERVER_RUNNING_MODE=STANDALONE",
		"K8S_NODE_IP_FOR_DEEPFLOW=127.0.0.1",
		"K8S_POD_IP_FOR_DEEPFLOW=127.0.0.1",
	}
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("component did not stop at configuration validation: %v", ctx.Err())
	}
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "Unmarshal yaml error") {
		t.Fatalf("expected the supplied invalid YAML to be rejected before service startup; err=%v output=%s", err, output)
	}
	if strings.Contains(string(output), "flag provided but not defined") {
		t.Fatalf("component reparsed caller flags: %s", output)
	}
}
