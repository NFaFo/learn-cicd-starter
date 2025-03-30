package auth

import (
	"errors"
	"net/http"
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
			name:    "valid ApiKey header",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
		{
			name:    "missing Authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "malformed header - wrong prefix",
			headers: http.Header{"Authorization": []string{"Bearer token"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "malformed header - only prefix",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "malformed header - empty value",
			headers: http.Header{"Authorization": []string{""}},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, key)
			}

			if (err != nil && tt.wantErr == nil) || (err == nil && tt.wantErr != nil) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			} else if err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("expected error message %q, got %q", tt.wantErr.Error(), err.Error())
			}
		})
	}
}
