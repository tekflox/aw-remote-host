package link

import "testing"

func TestWebSocketURL(t *testing.T) {
	cases := []struct {
		controlPlane string
		want         string
		wantErr      bool
	}{
		{"https://api.aw.tekflox.com", "wss://api.aw.tekflox.com/link", false},
		{"http://localhost:9123", "ws://localhost:9123/link", false},
		{"ftp://bad.example.com", "", true},
	}

	for _, tc := range cases {
		c := New(tc.controlPlane, "token")
		got, err := c.WebSocketURL()
		if tc.wantErr {
			if err == nil {
				t.Errorf("WebSocketURL(%q): expected error, got %q", tc.controlPlane, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("WebSocketURL(%q): unexpected error: %v", tc.controlPlane, err)
			continue
		}
		if got != tc.want {
			t.Errorf("WebSocketURL(%q) = %q, want %q", tc.controlPlane, got, tc.want)
		}
	}
}
