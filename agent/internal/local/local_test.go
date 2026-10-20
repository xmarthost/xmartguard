package local

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Audit A1 F5: a panicking handler answers with an error.
func TestHandlerPanicIsAnError(t *testing.T) {
	s := &Server{Root: map[string]Handler{
		"boom": func(context.Context, json.RawMessage) (any, error) { var m map[string]int; m["x"]++; return nil, nil },
	}}
	req := httptest.NewRequest("POST", "/v1/call", strings.NewReader(`{"action":"boom"}`))
	req = req.WithContext(context.WithValue(req.Context(), credKey{}, &unix.Ucred{Uid: 0}))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.OK || !strings.Contains(resp.Error, "internal error") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
