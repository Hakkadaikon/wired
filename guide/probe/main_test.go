package main

import (
	"net/http"
	"testing"
)

func TestFormatHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/plain")
	h.Set("Date", "Mon, 01 Jan 2024 00:00:00 GMT")
	h.Set("X-B", "2")
	h.Set("X-A", "1")

	got := formatHeaders(h)
	want := []string{"content-type: text/plain", "x-a: 1", "x-b: 2"}
	if len(got) != len(want) {
		t.Fatalf("formatHeaders(%v) = %v, want %v", h, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("formatHeaders(%v)[%d] = %q, want %q", h, i, got[i], want[i])
		}
	}
}

func TestFormatHeadersExcludesAnyDateLikeName(t *testing.T) {
	h := http.Header{}
	h.Set("X-Request-Date", "Mon, 01 Jan 2024 00:00:00 GMT")
	if got := formatHeaders(h); len(got) != 0 {
		t.Fatalf("formatHeaders(%v) = %v, want empty", h, got)
	}
}
