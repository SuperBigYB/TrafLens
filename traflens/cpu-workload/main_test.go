//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultPlanDoesNotCreateFiles(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if status := run([]string{"--output", filepath.Join(dir, "unused")}, &stdout, &stderr); status != 0 {
		t.Fatalf("plan failed: %d %s", status, stderr.String())
	}
	var plan map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil || plan["execute"] != false || plan["starts_network"] != false || plan["creates_files"] != false {
		t.Fatalf("plan promised execution: %s %v", stdout.Bytes(), err)
	}
	items, err := os.ReadDir(dir)
	if err != nil || len(items) != 0 {
		t.Fatalf("offline plan wrote files: %v %v", items, err)
	}
}

func TestInvalidExecutionNeverStartsSampling(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(parent, "run")
	for _, args := range [][]string{
		{"--execute", "--output", output},
		{"--execute", "--run", "cpu-example", "--output", output},
		{"--execute", "--run", "cpu-aaaaaaaaaaaaaaaaaaaaaaaa", "--seconds", "4", "--output", output},
		{"--execute", "--run", "cpu-aaaaaaaaaaaaaaaaaaaaaaaa", "--seconds", "21", "--output", output},
		{"--execute", "--run", "cpu-aaaaaaaaaaaaaaaaaaaaaaaa", "--output", "relative-output"},
		{"--execute", "--run", "cpu-aaaaaaaaaaaaaaaaaaaaaaaa", "--output", parent},
		{"--execute", "--run", "cpu-aaaaaaaaaaaaaaaaaaaaaaaa", "--output", output, "unexpected"},
	} {
		var stdout, stderr bytes.Buffer
		if status := run(args, &stdout, &stderr); status == 0 {
			t.Fatalf("invalid execution accepted: %v", args)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("rejected execution created output: %v %v", args, err)
		}
	}
}

func TestOutputRejectsPublicAndSymlinkParents(t *testing.T) {
	root := t.TempDir()
	public := filepath.Join(root, "public")
	private := filepath.Join(root, "private")
	if err := os.Mkdir(public, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(public, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(public, "run"), filepath.Join(link, "run"), private + "/../other"} {
		if err := validateOutput(path); err == nil {
			t.Fatalf("unsafe output accepted: %s", path)
		}
	}
	if err := validateOutput(filepath.Join(private, "run")); err != nil {
		t.Fatalf("fresh private output rejected: %v", err)
	}
}
