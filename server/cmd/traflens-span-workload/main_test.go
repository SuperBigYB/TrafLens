//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

type captureClient struct{ spans []*tracepb.ResourceSpans }

func (*captureClient) Start(context.Context) error { return nil }
func (*captureClient) Stop(context.Context) error  { return nil }
func (c *captureClient) UploadTraces(_ context.Context, spans []*tracepb.ResourceSpans) error {
	c.spans = append(c.spans, spans...)
	return nil
}

func TestSDKMeasuresAndCanonicallyExportsW3CParentContext(t *testing.T) {
	ctx := context.Background()
	capture := &captureClient{}
	exporter, err := otlptrace.New(ctx, capture)
	if err != nil {
		t.Fatal(err)
	}
	p := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", "unit-real-sdk"))))
	tracer := p.Tracer("unit-real-sdk")
	rootContext, root := tracer.Start(ctx, "unit.server", trace.WithSpanKind(trace.SpanKindServer))
	clientContext, outgoing := tracer.Start(rootContext, "unit.client", trace.WithSpanKind(trace.SpanKindClient))
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(clientContext, carrier)
	remote := propagation.TraceContext{}.Extract(ctx, carrier)
	if !trace.SpanContextFromContext(remote).IsRemote() {
		t.Fatal("W3C extraction did not preserve remote parent provenance")
	}
	backendContext, incoming := tracer.Start(remote, "unit.backend", trace.WithSpanKind(trace.SpanKindServer))
	_, internal := tracer.Start(backendContext, "unit.work", trace.WithSpanKind(trace.SpanKindInternal))
	internal.End()
	incoming.End()
	outgoing.End()
	root.End()
	if err := p.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	var actual []*tracepb.Span
	for _, resource := range capture.spans {
		for _, scope := range resource.ScopeSpans {
			actual = append(actual, scope.Spans...)
		}
	}
	if len(actual) != 4 {
		t.Fatalf("expected four real SDK exports, got %d", len(actual))
	}
	byName := map[string]*tracepb.Span{}
	for _, span := range actual {
		if len(span.TraceId) != 16 || len(span.SpanId) != 8 || span.StartTimeUnixNano == 0 || span.EndTimeUnixNano < span.StartTimeUnixNano {
			t.Fatal("SDK export lost measured identity/timestamps")
		}
		byName[span.Name] = span
	}
	for child, parent := range map[string]string{"unit.client": "unit.server", "unit.backend": "unit.client", "unit.work": "unit.backend"} {
		if !bytes.Equal(byName[child].TraceId, byName[parent].TraceId) || !bytes.Equal(byName[child].ParentSpanId, byName[parent].SpanId) {
			t.Fatalf("actual SDK W3C causal relation lost: %s -> %s", parent, child)
		}
	}
	if len(byName["unit.server"].ParentSpanId) != 0 {
		t.Fatal("new SDK root unexpectedly has a manufactured parent")
	}
}

func TestDefaultPlanCreatesNoFilesOrWork(t *testing.T) {
	directory := t.TempDir()
	var stdout, stderr bytes.Buffer
	if status := run([]string{"serve", "--role", "frontend", "--output", directory}, &stdout, &stderr); status != 0 {
		t.Fatalf("offline plan failed: %d %s", status, stderr.String())
	}
	var plan map[string]any
	if json.Unmarshal(stdout.Bytes(), &plan) != nil || plan["execute"] != false || plan["starts_network"] != false || plan["creates_files"] != false {
		t.Fatalf("unexpected offline plan: %s", stdout.String())
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 0 {
		t.Fatalf("offline plan wrote files: %v %v", files, err)
	}
}

func TestInvalidExecutionAndPublicOutputFailBeforeSideEffects(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	token := "span-aaaaaaaaaaaaaaaaaaaaaaaa"
	for _, args := range [][]string{
		{"serve", "--execute", "--run", token, "--output", directory},
		{"serve", "--execute", "--role", "unknown", "--run", token, "--output", directory},
		{"generate", "--execute", "--run", token, "--output", directory, "--requests", "5"},
		{"generate", "--execute", "--run", token, "--output", directory, "--seconds", "91"},
		{"generate", "--execute", "--run", "invalid", "--output", directory},
		{"generate", "--execute", "--run", token, "--output", filepath.Join(directory, "absent")},
		{"generate", "--execute", "--role", "frontend", "--run", token, "--output", directory},
	} {
		var stdout, stderr bytes.Buffer
		if status := run(args, &stdout, &stderr); status == 0 {
			t.Fatalf("bad execution accepted: %v", args)
		}
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := parse([]string{"generate", "--execute", "--run", token, "--output", directory}, &bytes.Buffer{}); err == nil {
		t.Fatal("public output directory accepted")
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 0 {
		t.Fatalf("rejected executions wrote output: %v %v", files, err)
	}
}
