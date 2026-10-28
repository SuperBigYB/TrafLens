package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

const maxProfile = 1024 * 1024
const maxResponse = 4096
const integrationPort = 39093

func execute() error {
	execFlag := flag.Bool("execute", false, "explicitly read and POST the verified profile")
	profilePath := flag.String("profile", "", "absolute runtime/pprof gzip file")
	expectedHash := flag.String("sha256", "", "expected SHA256 hex of the exact profile")
	name := flag.String("name", "", "cpu- followed by24 lowercase hex characters")
	from := flag.Int64("from", 0, "positive Epoch second metadata")
	until := flag.Int64("until", 0, "Epoch second metadata at or after from")
	port := flag.Int("port", integrationPort, "fixed loopback profiling integration port")
	flag.Parse()
	if flag.NArg() != 0 || *port != integrationPort {
		return errors.New("only named arguments and fixed port39093 are accepted")
	}
	if !*execFlag {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"execute": false, "reads_profile": false, "starts_network": false,
			"endpoint":          "http://127.0.0.1:39093/api/v1/profile/ingest",
			"max_profile_bytes": maxProfile, "max_response_bytes": maxResponse,
			"http_ack_is_not_ingestion": true,
		})
	}
	if !filepath.IsAbs(*profilePath) || filepath.Clean(*profilePath) != *profilePath {
		return errors.New("profile must be a canonical absolute file path")
	}
	if !regexp.MustCompile(`^cpu-[0-9a-f]{24}$`).MatchString(*name) {
		return errors.New("exact fresh CPU run label required")
	}
	if *from <= 0 || *until < *from || *until > 4294967295 {
		return errors.New("from/until must be ordered positive Epoch seconds within native UInt32 bounds")
	}
	if len(*expectedHash) != 64 {
		return errors.New("expected SHA256 must contain64 hex characters")
	}
	wanted, err := hex.DecodeString(*expectedHash)
	if err != nil {
		return errors.New("invalid expected SHA256")
	}
	info, err := os.Lstat(*profilePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > maxProfile {
		return errors.New("profile must be a regular gzip file of at most1MiB")
	}
	f, err := os.Open(*profilePath)
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(io.LimitReader(f, maxProfile+1))
	closeErr := f.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(body) < 2 || len(body) > maxProfile || body[0] != 0x1f || body[1] != 0x8b {
		return errors.New("profile is not a bounded gzip stream")
	}
	actual := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(actual[:], wanted) != 1 {
		return errors.New("profile SHA256 mismatch; no request sent")
	}
	query := url.Values{"format": {"pprof"}, "spyName": {"gospy"}, "name": {*name},
		"from": {strconv.FormatInt(*from, 10)}, "until": {strconv.FormatInt(*until, 10)},
		"sampleRate": {"100"}, "units": {"samples"}}
	endpoint := url.URL{Scheme: "http", Host: "127.0.0.1:39093", Path: "/api/v1/profile/ingest", RawQuery: query.Encode()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	// Raw pprof requires absent Content-Type: any value invokes the native
	// multipart branch. The decoder itself recognizes the gzip magic bytes.
	req.Header.Del("Content-Type")
	req.Header.Del("Content-Encoding")
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	rawResponse, err := io.ReadAll(io.LimitReader(response.Body, maxResponse))
	if err != nil {
		return err
	}
	ack := response.StatusCode >= 200 && response.StatusCode < 300
	responseHash := sha256.Sum256(rawResponse)
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"execute": true, "name": *name, "from": *from, "until": *until,
		"profile_bytes": len(body), "profile_sha256": hex.EncodeToString(actual[:]),
		"http_status": response.StatusCode, "http_acknowledged": ack,
		"ingestion_verified": false, "response_bytes_read": len(rawResponse),
		"response_at_read_limit": len(rawResponse) == maxResponse,
		"response_prefix_sha256": hex.EncodeToString(responseHash[:]),
		"source":                 "existing_native_pprof_integration_gospy",
	}); err != nil {
		return err
	}
	if !ack {
		return errors.New("profiling integration did not acknowledge HTTP2xx; ingestion is unverified")
	}
	return nil
}

func main() {
	if err := execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
