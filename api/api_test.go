package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go/netbird-pam/api"
)

func TestFetchPeers_Success(t *testing.T) {
	want := []api.Peer{{ID: "p1", IP: "100.99.1.2", UserID: "u1"}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token test-token" {
			t.Errorf("wrong auth header: %q", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("ip") != "100.99.1.2" {
			t.Errorf("expected ip query param, got %q", r.URL.RawQuery)
		}
		json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	client := api.NewClient(srv.Client(), srv.URL, "test-token")
	peers, err := client.FetchPeers(context.Background(), "100.99.1.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 1 || peers[0].ID != "p1" {
		t.Errorf("unexpected peers: %+v", peers)
	}
}

func TestFetchPeers_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := api.NewClient(srv.Client(), srv.URL, "test-token")
	_, err := client.FetchPeers(context.Background(), "100.99.1.2")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestFetchPeers_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]api.Peer{})
	}))
	defer srv.Close()

	client := api.NewClient(srv.Client(), srv.URL, "test-token")
	peers, err := client.FetchPeers(context.Background(), "100.99.1.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("expected empty peers, got %+v", peers)
	}
}

func TestFetchUsers_Success(t *testing.T) {
	want := []api.User{{ID: "u1", Email: "alice@example.com"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	client := api.NewClient(srv.Client(), srv.URL, "test-token")
	users, err := client.FetchUsers(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 || users[0].ID != "u1" {
		t.Errorf("unexpected users: %+v", users)
	}
}

func TestFetchUsers_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := api.NewClient(srv.Client(), srv.URL, "test-token")
	_, err := client.FetchUsers(context.Background())
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}
