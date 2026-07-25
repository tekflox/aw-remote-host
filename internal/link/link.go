// Package link holds the WebSocket client that dials the control plane's
// /link endpoint. This is a stub — the real protocol (handshake, heartbeat,
// command channel) is implemented in card 4; card 3 defines the server side.
package link

import (
	"fmt"
	"net/url"
)

// Client holds the connection parameters for a future /link session.
type Client struct {
	ControlPlane string // e.g. https://api.aw.tekflox.com
	Token        string
}

// New builds a Client from the CLI's --control-plane and --token flags.
func New(controlPlane, token string) *Client {
	return &Client{ControlPlane: controlPlane, Token: token}
}

// WebSocketURL returns the wss:// URL this client would dial.
func (c *Client) WebSocketURL() (string, error) {
	u, err := url.Parse(c.ControlPlane)
	if err != nil {
		return "", fmt.Errorf("parse control plane url: %w", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported control plane scheme %q", u.Scheme)
	}
	u.Path = "/link"
	return u.String(), nil
}

// Dial connects to the control plane's /link endpoint with
// "Authorization: Bearer <token>". Stub — real dial/handshake/reconnect
// logic comes in card 4.
func (c *Client) Dial() error {
	wsURL, err := c.WebSocketURL()
	if err != nil {
		return err
	}
	return fmt.Errorf("link.Dial not implemented yet (see card 4): would dial %s", wsURL)
}
