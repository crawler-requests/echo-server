package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

type replayCtxKey struct{}

// replayEcho executes the real echoHandler in-process against a synthetic
// request. Nothing touches the network listener, so the response is exactly
// what a client would receive for the same method/path/headers/body.
func replayEcho(method, path string, headers map[string]string, body string) map[string]any {
	start := time.Now()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	req.RemoteAddr = "127.0.0.1:0"
	req = req.WithContext(context.WithValue(req.Context(), replayCtxKey{}, true))
	rec := httptest.NewRecorder()
	echoHandler(rec, req)
	res := rec.Result()
	defer res.Body.Close()

	out := map[string]any{
		"status":       res.StatusCode,
		"headers":      res.Header,
		"content_type": res.Header.Get("Content-Type"),
		"duration_ms":  float64(time.Since(start).Microseconds()) / 1000.0,
		"body":         rec.Body.String(),
	}
	if strings.Contains(res.Header.Get("Content-Type"), "json") {
		var parsed any
		if json.Unmarshal(rec.Body.Bytes(), &parsed) == nil {
			out["json"] = parsed
		}
	}
	return out
}

func isReplay(r *http.Request) bool {
	v, _ := r.Context().Value(replayCtxKey{}).(bool)
	return v
}
