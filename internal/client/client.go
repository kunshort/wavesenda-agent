// Package client talks to WaveSenda, and only outward.
//
// The daemon opens connections; nothing opens connections to it. That is why
// there is no listener anywhere in this program, no port to firewall, and
// nothing to reach on a machine behind NAT.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	Base  string
	Token string
	http  *http.Client
}

type Job struct {
	ID         string         `json:"id"`
	Capability string         `json:"capability"`
	Arguments  map[string]any `json:"arguments"`
	Tier       string         `json:"tier"`
}

type jobsResponse struct {
	Jobs        []Job `json:"jobs"`
	PollSeconds int   `json:"poll_seconds"`
}

type heartbeatResponse struct {
	Grants      []string `json:"grants"`
	PollSeconds int      `json:"poll_seconds"`
}

type Alert struct {
	Kind      string `json:"kind"`
	Summary   string `json:"summary"`
	Suggested string `json:"suggested,omitempty"`
}

func New(base, token string) *Client {
	return &Client{
		Base:  strings.TrimSuffix(base, "/"),
		Token: token,
		http:  &http.Client{Timeout: 45 * time.Second},
	}
}

func (c *Client) post(ctx context.Context, path string, body any, into any) error {
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader([]byte("{}"))
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Server-Token", c.Token)

	return c.do(request, into)
}

func (c *Client) do(request *http.Request, into any) error {
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized {
		// The token has been revoked, or this server was removed. Said plainly
		// so the log shows a decision rather than a network wobble.
		return fmt.Errorf("this server is no longer registered")
	}
	if response.StatusCode >= 300 {
		return fmt.Errorf("server answered %d", response.StatusCode)
	}
	if into == nil {
		return nil
	}
	return json.NewDecoder(response.Body).Decode(into)
}

func (c *Client) Register(ctx context.Context, version string, facts map[string]string) error {
	return c.post(ctx, "/register/", map[string]any{"version": version, "facts": facts}, nil)
}

func (c *Client) Jobs(ctx context.Context) ([]Job, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/jobs/", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Server-Token", c.Token)

	var body jobsResponse
	if err := c.do(request, &body); err != nil {
		return nil, err
	}
	return body.Jobs, nil
}

func (c *Client) Result(ctx context.Context, jobID string, ok bool, output string, ms int64) error {
	return c.post(ctx, "/jobs/"+jobID+"/result/", map[string]any{
		"ok": ok, "output": output, "duration_ms": ms,
	}, nil)
}

// Heartbeat says we are alive and collects the current grant list.
func (c *Client) Heartbeat(ctx context.Context, alerts []Alert) ([]string, error) {
	var body heartbeatResponse
	if err := c.post(ctx, "/heartbeat/", map[string]any{"alerts": alerts}, &body); err != nil {
		return nil, err
	}
	return body.Grants, nil
}
