package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Peer struct {
	ID     string `json:"id"`
	IP     string `json:"ip"`
	UserID string `json:"user_id"`
}

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type StatusError struct {
	Path       string
	StatusCode int
	Body       string
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("GET %s returned %d %s", e.Path, e.StatusCode, http.StatusText(e.StatusCode))
	if e.Body != "" {
		msg += ": " + e.Body
	}
	return msg
}

type Client struct {
	HTTPClient *http.Client
	BaseURL    string
	Token      string
}

func NewClient(httpClient *http.Client, baseURL, token string) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		HTTPClient: httpClient,
		BaseURL:    baseURL,
		Token:      token,
	}
}

func (c *Client) fetch(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &StatusError{
			Path:       path,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(body)),
		}
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) FetchPeers(ctx context.Context, ip string) ([]Peer, error) {
	var peers []Peer
	params := url.Values{}
	params.Add("ip", ip)
	err := c.fetch(ctx, "/api/peers?"+params.Encode(), &peers)
	return peers, err
}

func (c *Client) FetchUsers(ctx context.Context) ([]User, error) {
	var users []User
	err := c.fetch(ctx, "/api/users", &users)
	return users, err
}
