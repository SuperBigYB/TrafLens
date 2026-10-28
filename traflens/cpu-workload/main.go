//go:build linux

// cpu-workload samples only its own finite Go process. It never uploads data.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/bits"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strconv"
	"syscall"
	"time"
)

var runToken = regexp.MustCompile(`^cpu-[0-9a-f]{24}$`)
var checksumSink uint64

type config struct {
	execute bool
	seconds int
	run     string
	output  string
}

type usage struct {
	UserNS   int64 `json:"user_ns"`
	SystemNS int64 `json:"system_ns"`
}

type receipt struct {
	Run                  string `json:"run"`
	Source               string `json:"source"`
	SamplingScope        string `json:"sampling_scope"`
	PID                  int    `json:"pid"`
	TargetSeconds        int    `json:"target_seconds"`
	StartedAt            string `json:"started_at"`
	FinishedAt           string `json:"finished_at"`
	StartedUnixNS        int64  `json:"started_unix_ns"`
	FinishedUnixNS       int64  `json:"finished_unix_ns"`
	WallDurationNS       int64  `json:"wall_duration_ns"`
	SelfCPU              usage  `json:"self_cpu"`
	HotLoopBatches       uint64 `json:"hot_loop_batches"`
	Checksum             string `json:"checksum"`
	WorkloadHotFunction  string `json:"workload_hot_function"`
	ProfileFile          string `json:"profile_file"`
	ProfileBytes         int64  `json:"profile_bytes"`
	ProfileSHA256        string `json:"profile_sha256"`
	StopReason           string `json:"stop_reason"`
	CompletedDuration    bool   `json:"completed_duration"`
	SampleContentChecked bool   `json:"sample_content_checked"`
}

func parse(args []string, stderr io.Writer) (config, error) {
	c := config{}
	f := flag.NewFlagSet("cpu-workload", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.BoolVar(&c.execute, "execute", false, "explicitly run finite self CPU sampling")
	f.IntVar(&c.seconds, "seconds", 10, "sampling workload duration, 5..20 seconds")
	f.StringVar(&c.run, "run", "", "fresh cpu- followed by24 lowercase hexadecimal characters")
	f.StringVar(&c.output, "output", "", "new absolute private output directory, with an owned private parent")
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 || c.seconds < 5 || c.seconds > 20 {
		return c, errors.New("only named flags and a duration of5..20 seconds are accepted")
	}
	if c.execute && !runToken.MatchString(c.run) {
		return c, errors.New("execute requires a fresh cpu- followed by24 lowercase hex characters")
	}
	return c, nil
}

func validateOutput(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("output must be a canonical absolute new directory")
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return errors.New("output parent must exist and have no symlink components")
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("output parent must be an existing private directory")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("output parent must belong to the current effective user")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("output already exists or cannot be checked")
	}
	return nil
}

func currentUsage() (usage, error) {
	var r syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &r); err != nil {
		return usage{}, err
	}
	return usage{r.Utime.Nano(), r.Stime.Nano()}, nil
}

//go:noinline
func traflensCPUHotLoop(seed uint64) uint64 {
	for i := uint64(0); i < 65536; i++ {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		seed = bits.RotateLeft64(seed+0x9e3779b97f4a7c15+i, 11)
	}
	return seed
}

func sample(c config) (receipt, error) {
	if err := validateOutput(c.output); err != nil {
		return receipt{}, err
	}
	if err := os.Mkdir(c.output, 0700); err != nil {
		return receipt{}, err
	}
	profilePath := filepath.Join(c.output, "cpu.pprof")
	f, err := os.OpenFile(profilePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return receipt{}, err
	}
	defer f.Close()
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)
	before, err := currentUsage()
	if err != nil {
		return receipt{}, err
	}
	signals, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signals, time.Duration(c.seconds)*time.Second)
	defer cancel()
	started := time.Now()
	if err := pprof.StartCPUProfile(f); err != nil {
		return receipt{}, err
	}
	var batches uint64
	seed := uint64(0x8a5cd789635d2dff)
	pprof.Do(ctx, pprof.Labels("traflens_run", c.run), func(ctx context.Context) {
		for ctx.Err() == nil {
			seed = traflensCPUHotLoop(seed)
			batches++
		}
		checksumSink = seed
	})
	pprof.StopCPUProfile()
	if err := f.Close(); err != nil {
		return receipt{}, err
	}
	finished := time.Now()
	after, err := currentUsage()
	if err != nil {
		return receipt{}, err
	}
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return receipt{}, err
	}
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return receipt{}, errors.New("runtime did not produce a gzip pprof file")
	}
	hash := sha256.Sum256(data)
	reason := "duration"
	if signals.Err() != nil {
		reason = "signal"
	}
	r := receipt{Run: c.run, Source: "go_runtime_pprof_self", SamplingScope: "current process only",
		PID: os.Getpid(), TargetSeconds: c.seconds, StartedAt: started.UTC().Format(time.RFC3339Nano),
		FinishedAt: finished.UTC().Format(time.RFC3339Nano), StartedUnixNS: started.UnixNano(), FinishedUnixNS: finished.UnixNano(),
		WallDurationNS: finished.Sub(started).Nanoseconds(), SelfCPU: usage{after.UserNS - before.UserNS, after.SystemNS - before.SystemNS},
		HotLoopBatches: batches, Checksum: strconv.FormatUint(checksumSink, 10), WorkloadHotFunction: "main.traflensCPUHotLoop",
		ProfileFile: "cpu.pprof", ProfileBytes: int64(len(data)), ProfileSHA256: hex.EncodeToString(hash[:]),
		StopReason: reason, CompletedDuration: reason == "duration", SampleContentChecked: false}
	output, err := os.OpenFile(filepath.Join(c.output, "receipt.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return receipt{}, err
	}
	err = json.NewEncoder(output).Encode(r)
	closeErr := output.Close()
	if err != nil {
		return receipt{}, err
	}
	return r, closeErr
}

func run(args []string, stdout, stderr io.Writer) int {
	c, err := parse(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if !c.execute {
		_ = json.NewEncoder(stdout).Encode(map[string]any{"execute": false, "starts_network": false,
			"creates_files": false, "sampling_scope": "current process only", "source": "go_runtime_pprof_self",
			"target_seconds": c.seconds, "max_seconds": 20, "content_qualification": "real sample content requires later pprof inspection"})
		return 0
	}
	r, err := sample(c)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(r); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
