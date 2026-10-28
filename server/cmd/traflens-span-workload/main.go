//go:build linux

// A finite, explicitly instrumented two-service HTTP workload. No execution is
// performed unless --execute is supplied; all network destinations are fixed
// loopback endpoints inside the caller's owned network namespace.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

const exportEndpoint = "http://127.0.0.1:39093/api/v1/otel/trace"
const source = "OpenTelemetry SDK explicit instrumentation; native OTLP integration, not eBPF"

var runPattern = regexp.MustCompile(`^span-[0-9a-f]{24}$`)
var tracePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var spanPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

type config struct {
	Command  string
	Execute  bool
	Role     string
	Run      string
	Output   string
	Seconds  int
	Requests int
}

func parse(args []string, stderr io.Writer) (config, error) {
	c := config{Command: "plan"}
	if len(args) > 0 && (args[0] == "serve" || args[0] == "generate") {
		c.Command, args = args[0], args[1:]
	}
	f := flag.NewFlagSet("traflens-span-workload", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.BoolVar(&c.Execute, "execute", false, "explicitly execute the finite workload")
	f.StringVar(&c.Role, "role", "", "serve role: frontend or backend")
	f.StringVar(&c.Run, "run", "", "span- followed by24 lowercase hex characters")
	f.StringVar(&c.Output, "output", "", "existing owned private directory; output files must be new")
	f.IntVar(&c.Seconds, "seconds", 90, "total lifetime, 5..90 seconds")
	f.IntVar(&c.Requests, "requests", 2, "finite unique root requests, 1..4; default main plus control")
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 || c.Seconds < 5 || c.Seconds > 90 || c.Requests < 1 || c.Requests > 4 {
		return c, errors.New("named flags,5..90seconds and1..4requests required")
	}
	if c.Execute {
		if !runPattern.MatchString(c.Run) || c.Command == "plan" || (c.Command == "serve" && c.Role != "frontend" && c.Role != "backend") || (c.Command == "generate" && c.Role != "") {
			return c, errors.New("explicit serve/frontend|backend or generate and fresh span run required")
		}
		if err := privateDirectory(c.Output); err != nil {
			return c, err
		}
	}
	return c, nil
}

func privateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("canonical absolute existing output directory required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("output cannot contain symlink components")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("output must be a private existing directory")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("output must belong to the current effective user")
	}
	return nil
}

func newFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}

func save(path string, value any) error {
	f, err := newFile(path)
	if err != nil {
		return err
	}
	err = json.NewEncoder(f).Encode(value)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}
}

func attributes(values []attribute.KeyValue) map[string]any {
	result := make(map[string]any, len(values))
	for _, value := range values {
		result[string(value.Key)] = value.Value.AsInterface()
	}
	return result
}

type witnessExporter struct {
	delegate sdktrace.SpanExporter
	file     *os.File
	mu       sync.Mutex
	count    int
	errors   []string
}

func (e *witnessExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, span := range spans {
		parent := ""
		if span.Parent().IsValid() {
			parent = span.Parent().SpanID().String()
		}
		scope := span.InstrumentationScope()
		row := map[string]any{"source": source, "name": span.Name(), "trace_id": span.SpanContext().TraceID().String(),
			"span_id": span.SpanContext().SpanID().String(), "parent_span_id": parent,
			"parent_remote": span.Parent().IsRemote(), "span_kind": int(span.SpanKind()),
			"start_unix_ns": span.StartTime().UnixNano(), "end_unix_ns": span.EndTime().UnixNano(),
			"trace_flags": span.SpanContext().TraceFlags().String(), "trace_state": span.SpanContext().TraceState().String(),
			"attributes": attributes(span.Attributes()), "resource": attributes(span.Resource().Attributes()),
			"status_code": span.Status().Code.String(), "status_description": span.Status().Description,
			"scope":              map[string]string{"name": scope.Name, "version": scope.Version, "schema_url": scope.SchemaURL},
			"dropped_attributes": span.DroppedAttributes(), "dropped_events": span.DroppedEvents(),
			"dropped_links": span.DroppedLinks(), "child_span_count": span.ChildSpanCount()}
		if !span.SpanContext().IsValid() || span.StartTime().IsZero() || span.EndTime().Before(span.StartTime()) {
			return errors.New("SDK returned an invalid measured span")
		}
		if err := json.NewEncoder(e.file).Encode(row); err != nil {
			e.errors = append(e.errors, err.Error())
			return err
		}
		e.count++
	}
	if err := e.file.Sync(); err != nil {
		e.errors = append(e.errors, err.Error())
		return err
	}
	if err := e.delegate.ExportSpans(ctx, spans); err != nil {
		e.errors = append(e.errors, err.Error())
		return err
	}
	return nil
}

func (e *witnessExporter) Shutdown(ctx context.Context) error { return e.delegate.Shutdown(ctx) }

type wireClient struct {
	output string
	file   *os.File
	client *http.Client
	mu     sync.Mutex
	count  int
	acks   int
}

func (w *wireClient) Start(context.Context) error { return nil }
func (w *wireClient) Stop(context.Context) error {
	w.client.CloseIdleConnections()
	return nil
}

func (w *wireClient) UploadTraces(ctx context.Context, resourceSpans []*tracepb.ResourceSpans) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.count++
	if w.count > 8 {
		return errors.New("finite per-service export budget exceeded")
	}
	// The official otlptrace.Exporter produced these canonical ResourceSpans
	// from real ReadOnlySpan snapshots; no Span protobuf is manufactured here.
	body, err := proto.Marshal(&collector.ExportTraceServiceRequest{ResourceSpans: resourceSpans})
	if err != nil || len(body) == 0 || len(body) > 256*1024 {
		return errors.New("SDK protobuf export is empty or exceeds finite byte budget")
	}
	name := fmt.Sprintf("%04d.pb", w.count)
	f, err := newFile(filepath.Join(w.output, "exports", name))
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	hash := sha256.Sum256(body)
	evidence := map[string]any{"batch": w.count, "file": "exports/" + name, "bytes": len(body),
		"sha256": hex.EncodeToString(hash[:]), "http_acknowledged": false, "storage_verified": false}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exportEndpoint, bytes.NewReader(body))
	if err == nil {
		req.Header.Set("Content-Type", "application/x-protobuf")
		var response *http.Response
		response, err = w.client.Do(req)
		if err == nil {
			data, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
			response.Body.Close()
			evidence["http_status"] = response.StatusCode
			evidence["response_bytes"] = len(data)
			if readErr != nil || len(data) > 4096 {
				err = errors.New("OTLP integration response unreadable or oversized")
			} else if response.StatusCode < 200 || response.StatusCode >= 300 {
				err = errors.New("native OTLP integration did not HTTP-acknowledge export")
			} else {
				w.acks++
				evidence["http_acknowledged"] = true
			}
		}
	}
	if err != nil {
		evidence["error"] = err.Error()
	}
	if writeErr := json.NewEncoder(w.file).Encode(evidence); writeErr != nil {
		return writeErr
	}
	if syncErr := w.file.Sync(); syncErr != nil {
		return syncErr
	}
	return err
}

func provider(c config) (*sdktrace.TracerProvider, *witnessExporter, *wireClient, func(), error) {
	if err := os.Mkdir(filepath.Join(c.Output, "exports"), 0700); err != nil {
		return nil, nil, nil, nil, err
	}
	spanFile, err := newFile(filepath.Join(c.Output, "spans.jsonl"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	wireFile, err := newFile(filepath.Join(c.Output, "wire.jsonl"))
	if err != nil {
		spanFile.Close()
		return nil, nil, nil, nil, err
	}
	wire := &wireClient{output: c.Output, file: wireFile, client: client(3 * time.Second)}
	exporter, err := otlptrace.New(context.Background(), wire)
	if err != nil {
		spanFile.Close()
		wireFile.Close()
		return nil, nil, nil, nil, err
	}
	witness := &witnessExporter{delegate: exporter, file: spanFile}
	service := c.Run + "-front"
	if c.Role == "backend" {
		service = c.Run + "-back"
	}
	res := resource.NewSchemaless(attribute.String("service.name", service), attribute.String("service.instance.id", c.Run+"-"+c.Role), attribute.String("traflens.run", c.Run))
	p := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSyncer(witness))
	return p, witness, wire, func() { spanFile.Close(); wireFile.Close() }, nil
}

func kinds(count int) []string {
	result := []string{"main"}
	if count >= 2 {
		result = append(result, "control")
	}
	for i := 2; i < count; i++ {
		result = append(result, "control-"+strconv.Itoa(i))
	}
	return result
}

func httpAttributes(c config, path, host string) []attribute.KeyValue {
	return []attribute.KeyValue{attribute.String("http.method", "GET"), attribute.String("http.target", path),
		attribute.String("http.flavor", "1.1"), attribute.String("http.scheme", "http"),
		attribute.String("http.host", host), attribute.String("http.url", "http://"+host+path),
		attribute.String("traflens.run", c.Run)}
}

type backendResponse struct {
	Run            string `json:"run"`
	Kind           string `json:"kind"`
	TraceID        string `json:"trace_id"`
	ServerSpanID   string `json:"server_span_id"`
	InternalSpanID string `json:"internal_span_id"`
	ParentSpanID   string `json:"received_parent_span_id"`
	Checksum       string `json:"checksum"`
}

type frontendResponse struct {
	Run          string          `json:"run"`
	Kind         string          `json:"kind"`
	TraceID      string          `json:"trace_id"`
	ServerSpanID string          `json:"server_span_id"`
	ClientSpanID string          `json:"client_span_id"`
	Backend      backendResponse `json:"backend"`
}

//go:noinline
func measuredWork() uint64 {
	x := uint64(0x8a5cd789635d2dff)
	for i := uint64(0); i < 65536; i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		x += i
	}
	return x
}

func backend(ctx context.Context, c config, tracer trace.Tracer, span trace.Span, parent trace.SpanContext, kind, path string) backendResponse {
	_, internal := tracer.Start(ctx, "backend.work", trace.WithSpanKind(trace.SpanKindInternal), trace.WithAttributes(httpAttributes(c, path, "127.0.0.1:18082")...))
	value := measuredWork()
	internal.SetAttributes(attribute.Int("http.status_code", 200))
	internal.SetStatus(codes.Ok, "finite internal workload completed")
	internalID := internal.SpanContext().SpanID().String()
	internal.End()
	return backendResponse{Run: c.Run, Kind: kind, TraceID: span.SpanContext().TraceID().String(), ServerSpanID: span.SpanContext().SpanID().String(),
		InternalSpanID: internalID, ParentSpanID: parent.SpanID().String(), Checksum: strconv.FormatUint(value, 10)}
}

func frontend(ctx context.Context, c config, tracer trace.Tracer, span trace.Span, kind, path string) (frontendResponse, error) {
	ctx, child := tracer.Start(ctx, "frontend.client", trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(httpAttributes(c, path, "127.0.0.1:18082")...))
	defer child.End()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:18082"+path, nil)
	if err != nil {
		return frontendResponse{}, err
	}
	request.Header.Set("X-TrafLens-Run", c.Run)
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(request.Header))
	response, err := client(12 * time.Second).Do(request)
	if err != nil {
		child.RecordError(err)
		child.SetStatus(codes.Error, "actual backend HTTP failed")
		return frontendResponse{}, err
	}
	defer response.Body.Close()
	child.SetAttributes(attribute.Int("http.status_code", response.StatusCode))
	body, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(body) > 16384 || response.StatusCode != 200 {
		child.SetStatus(codes.Error, "actual backend HTTP response failed")
		return frontendResponse{}, errors.New("bounded backend response failed")
	}
	var actual backendResponse
	if json.Unmarshal(body, &actual) != nil || actual.Run != c.Run || actual.Kind != kind || actual.TraceID != span.SpanContext().TraceID().String() || actual.ParentSpanID != child.SpanContext().SpanID().String() {
		child.SetStatus(codes.Error, "actual propagated backend identity differs")
		return frontendResponse{}, errors.New("backend did not preserve the actual W3C parent context")
	}
	child.SetStatus(codes.Ok, "actual backend HTTP completed")
	return frontendResponse{Run: c.Run, Kind: kind, TraceID: span.SpanContext().TraceID().String(), ServerSpanID: span.SpanContext().SpanID().String(),
		ClientSpanID: child.SpanContext().SpanID().String(), Backend: actual}, nil
}

func serve(ctx context.Context, c config, stdout io.Writer) (result map[string]any, returnErr error) {
	started := time.Now()
	result = map[string]any{"source": source, "mode": "serve", "role": c.Role, "run": c.Run, "pid": os.Getpid(), "pass": false, "storage_verified": false}
	p, witness, wire, closeFiles, err := provider(c)
	if err != nil {
		return result, err
	}
	defer closeFiles()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.Shutdown(shutdown); err != nil && returnErr == nil {
			returnErr = err
		}
		witness.mu.Lock()
		result["sdk_exported_spans"], result["export_errors"] = witness.count, append([]string{}, witness.errors...)
		ok := witness.count == 2*c.Requests && len(witness.errors) == 0
		witness.mu.Unlock()
		wire.mu.Lock()
		result["http_acknowledged_batches"], result["wire_batches"] = wire.acks, wire.count
		ok = ok && wire.acks == 2*c.Requests && wire.count == 2*c.Requests
		wire.mu.Unlock()
		if len(witness.errors) != 0 && returnErr == nil {
			returnErr = errors.New("actual SDK export failed")
		}
		result["started_unix_ns"], result["finished_unix_ns"] = started.UnixNano(), time.Now().UnixNano()
		result["pass"] = returnErr == nil && ok
		if returnErr != nil {
			result["error"] = returnErr.Error()
		}
		if err := save(filepath.Join(c.Output, "receipt.json"), result); err != nil && returnErr == nil {
			returnErr = err
		}
	}()
	port, host := 18081, "127.0.0.1:18081"
	if c.Role == "backend" {
		port, host = 18082, "127.0.0.1:18082"
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return result, err
	}
	tracer := p.Tracer("traflens.finite-http", trace.WithInstrumentationVersion("1"))
	done := make(chan struct{}, 1)
	var mu sync.Mutex
	seen := make(map[string]bool)
	completed := 0
	var requestErrors []string
	allowed := make(map[string]bool)
	for _, kind := range kinds(c.Requests) {
		allowed[kind] = true
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		kind := strings.TrimPrefix(request.URL.Path, "/traflens-span/"+c.Run+"/")
		ip, _, _ := net.SplitHostPort(request.RemoteAddr)
		if request.Method != http.MethodGet || request.URL.RawQuery != "" || !net.ParseIP(ip).IsLoopback() || request.Header.Get("X-TrafLens-Run") != c.Run || !allowed[kind] || request.URL.Path != "/traflens-span/"+c.Run+"/"+kind {
			http.Error(w, "outside finite workload", 400)
			return
		}
		extracted := propagation.TraceContext{}.Extract(request.Context(), propagation.HeaderCarrier(request.Header))
		parent := trace.SpanContextFromContext(extracted)
		if c.Role == "backend" && (!parent.IsValid() || !parent.IsRemote()) || c.Role == "frontend" && parent.IsValid() {
			http.Error(w, "unexpected W3C parent context", 400)
			return
		}
		mu.Lock()
		if seen[kind] || len(seen) >= c.Requests {
			mu.Unlock()
			http.Error(w, "duplicate or excess finite request", 409)
			return
		}
		seen[kind] = true
		mu.Unlock()
		measured, span := tracer.Start(extracted, c.Role+".server", trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(httpAttributes(c, request.URL.Path, host)...))
		var response any
		var err error
		if c.Role == "backend" {
			response = backend(measured, c, tracer, span, parent, kind, request.URL.Path)
		} else {
			response, err = frontend(measured, c, tracer, span, kind, request.URL.Path)
		}
		status := 200
		if err != nil {
			status = 502
			span.RecordError(err)
			span.SetStatus(codes.Error, "actual HTTP chain failed")
			response = map[string]string{"error": err.Error()}
		} else {
			span.SetStatus(codes.Ok, "actual HTTP handling completed")
		}
		span.SetAttributes(attribute.Int("http.status_code", status))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		writeErr := json.NewEncoder(w).Encode(response)
		span.End()
		mu.Lock()
		if err != nil {
			requestErrors = append(requestErrors, err.Error())
		}
		if writeErr != nil {
			requestErrors = append(requestErrors, writeErr.Error())
		}
		completed++
		if completed == c.Requests {
			done <- struct{}{}
		}
		mu.Unlock()
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8192}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(listener) }()
	ready := map[string]any{"event": "ready", "run": c.Run, "role": c.Role, "pid": os.Getpid(), "listen": host, "source": source}
	if err := save(filepath.Join(c.Output, "ready.json"), ready); err != nil {
		server.Close()
		return result, err
	}
	json.NewEncoder(stdout).Encode(ready)
	select {
	case <-done:
		result["stop_reason"] = "requests_completed"
	case <-ctx.Done():
		result["stop_reason"] = "signal"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result["stop_reason"] = "deadline"
		}
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			returnErr = err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		server.Close()
		if returnErr == nil {
			returnErr = err
		}
	}
	mu.Lock()
	result["completed_requests"], result["request_errors"] = completed, append([]string{}, requestErrors...)
	result["request_contract_completed"] = completed == c.Requests && len(requestErrors) == 0
	if len(requestErrors) != 0 && returnErr == nil {
		returnErr = errors.New("finite measured request contract did not complete")
	}
	mu.Unlock()
	return result, returnErr
}

func generate(ctx context.Context, c config) (map[string]any, error) {
	result := map[string]any{"source": source, "mode": "generate", "run": c.Run, "pid": os.Getpid(), "pass": false, "storage_verified": false}
	f, err := newFile(filepath.Join(c.Output, "requests.jsonl"))
	if err != nil {
		return result, err
	}
	defer f.Close()
	traces := []string{}
	traceSet := map[string]bool{}
	for _, kind := range kinds(c.Requests) {
		path := "/traflens-span/" + c.Run + "/" + kind
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:18081"+path, nil)
		if err != nil {
			return result, err
		}
		request.Header.Set("X-TrafLens-Run", c.Run)
		started := time.Now()
		response, err := client(20 * time.Second).Do(request)
		if err != nil {
			return result, err
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		response.Body.Close()
		if err != nil || len(body) > 16384 || response.StatusCode != 200 {
			return result, errors.New("actual finite frontend request failed")
		}
		var actual frontendResponse
		if json.Unmarshal(body, &actual) != nil || actual.Run != c.Run || actual.Kind != kind || !tracePattern.MatchString(actual.TraceID) || actual.TraceID == strings.Repeat("0", 32) || traceSet[actual.TraceID] || actual.Backend.TraceID != actual.TraceID || actual.Backend.ParentSpanID != actual.ClientSpanID {
			return result, errors.New("actual response trace/parent identities differ from measured chain")
		}
		spanIDs := map[string]bool{}
		for _, id := range []string{actual.ServerSpanID, actual.ClientSpanID, actual.Backend.ServerSpanID, actual.Backend.InternalSpanID} {
			if !spanPattern.MatchString(id) || id == strings.Repeat("0", 16) || spanIDs[id] {
				return result, errors.New("actual chain span IDs are missing or duplicated")
			}
			spanIDs[id] = true
		}
		traceSet[actual.TraceID] = true
		traces = append(traces, actual.TraceID)
		if err := json.NewEncoder(f).Encode(map[string]any{"kind": kind, "started_unix_ns": started.UnixNano(), "finished_unix_ns": time.Now().UnixNano(), "http_status": response.StatusCode, "actual_response": actual}); err != nil {
			return result, err
		}
	}
	result["completed_requests"], result["trace_ids"], result["pass"] = len(traces), traces, true
	if err := f.Sync(); err != nil {
		return result, err
	}
	return result, save(filepath.Join(c.Output, "receipt.json"), result)
}

func run(args []string, stdout, stderr io.Writer) int {
	c, err := parse(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if !c.Execute {
		json.NewEncoder(stdout).Encode(map[string]any{"execute": false, "starts_network": false, "creates_files": false, "source": source,
			"max_root_requests": 4, "spans_per_request": 4, "frontend_port": 18081, "backend_port": 18082, "otlp_endpoint": exportEndpoint})
		return 0
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, time.Duration(c.Seconds)*time.Second)
	defer cancel()
	var result map[string]any
	if c.Command == "serve" {
		result, err = serve(ctx, c, stdout)
	} else {
		result, err = generate(ctx, c)
	}
	if err != nil {
		result["pass"], result["error"] = false, err.Error()
		fmt.Fprintln(stderr, err)
		if _, statErr := os.Lstat(filepath.Join(c.Output, "receipt.json")); errors.Is(statErr, os.ErrNotExist) {
			if saveErr := save(filepath.Join(c.Output, "receipt.json"), result); saveErr != nil {
				fmt.Fprintln(stderr, saveErr)
			}
		}
	}
	json.NewEncoder(stdout).Encode(result)
	if err != nil {
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
