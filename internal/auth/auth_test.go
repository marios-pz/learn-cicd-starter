package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "No authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed header - missing prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			wantKey: "",
			wantErr: errContains("malformed authorization header"),
		},
		{
			name: "Malformed header - no token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey: "",
			wantErr: errContains("malformed authorization header"),
		},
		{
			name: "Valid ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if tt.wantErr != nil {
				if err == nil || !errorContains(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, got)
			}
		})
	}
}

// helper to match error messages
func errorContains(err, wantErr error) bool {
	if wantErr == nil {
		return err == nil
	}
	return err != nil && strings.Contains(err.Error(), wantErr.Error())
}

// helper to use string comparison for error
func errContains(msg string) error {
	return &errString{msg}
}

type errString struct{ s string }

func (e *errString) Error() string { return e.s }
