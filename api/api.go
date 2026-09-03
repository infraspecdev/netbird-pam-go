package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
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
