package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go/netbird-pam/api"
)

func makeServer(t *testing.T, peers []api.Peer, users []api.User) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/peers":
			json.NewEncoder(w).Encode(peers)
		case "/api/users":
			json.NewEncoder(w).Encode(users)
		}
	}))
}

func useServer(t *testing.T, srv *httptest.Server) {
	t.Helper()
	f, err := os.CreateTemp("", "netbird-pam-*.env")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, "NETBIRD_TOKEN=test-token\nNETBIRD_MANAGEMENT_URL=%s\n", srv.URL)
	f.Close()
	old := configPath
	configPath = f.Name()
	t.Cleanup(func() {
		configPath = old
		os.Remove(f.Name())
	})
}

func TestMain(m *testing.M) {
	initLogger()
	f, _ := os.CreateTemp("", "netbird-pam-*.env")
	fmt.Fprintf(f, "NETBIRD_TOKEN=test-token\nNETBIRD_MANAGEMENT_URL=http://placeholder\n")
	f.Close()
	configPath = f.Name()
	defer os.Remove(f.Name())
	os.Exit(m.Run())
}

func TestAuthorize_NonNetbirdIP(t *testing.T) {
	result := Authorize("192.168.1.1", "alice", http.DefaultClient)
	if result != pamSuccess {
		t.Errorf("expected pamSuccess, got %d", result)
	}
}

func TestAuthorize_Allowed(t *testing.T) {
	peers := []api.Peer{{ID: "p1", IP: "100.99.1.2", UserID: "u1"}}
	users := []api.User{{ID: "u1", Email: "alice.smith@example.com"}}
	srv := makeServer(t, peers, users)
	defer srv.Close()
	useServer(t, srv)

	result := Authorize("100.99.1.2", "alice-smith", srv.Client())
	if result != pamSuccess {
		t.Errorf("expected pamSuccess, got %d", result)
	}
}

func TestAuthorize_WrongUsername(t *testing.T) {
	peers := []api.Peer{{ID: "p1", IP: "100.99.1.2", UserID: "u1"}}
	users := []api.User{{ID: "u1", Email: "alice.smith@example.com"}}
	srv := makeServer(t, peers, users)
	defer srv.Close()
	useServer(t, srv)

	result := Authorize("100.99.1.2", "alice", srv.Client())
	if result != pamDeny {
		t.Errorf("expected pamDeny, got %d", result)
	}
}

func TestAuthorize_NoPeer(t *testing.T) {
	srv := makeServer(t, []api.Peer{}, []api.User{})
	defer srv.Close()
	useServer(t, srv)

	result := Authorize("100.99.1.2", "alice", srv.Client())
	if result != pamDeny {
		t.Errorf("expected pamDeny, got %d", result)
	}
}

func TestAuthorize_EmptyUserID(t *testing.T) {
	peers := []api.Peer{{ID: "p1", IP: "100.99.1.2", UserID: ""}}
	users := []api.User{}
	srv := makeServer(t, peers, users)
	defer srv.Close()
	useServer(t, srv)

	result := Authorize("100.99.1.2", "alice", srv.Client())
	if result != pamDeny {
		t.Errorf("expected pamDeny for empty user_id, got %d", result)
	}
}

func TestAuthorize_ImpersonationAttempt(t *testing.T) {
	peers := []api.Peer{{ID: "p1", IP: "100.99.1.2", UserID: "u1"}}
	users := []api.User{
		{ID: "u1", Email: "alice@example.com"},
		{ID: "u2", Email: "bob@example.com"},
	}
	srv := makeServer(t, peers, users)
	defer srv.Close()
	useServer(t, srv)

	result := Authorize("100.99.1.2", "bob", srv.Client())
	if result != pamDeny {
		t.Errorf("expected pamDeny for impersonation attempt, got %d", result)
	}
}

func TestAuthorize_UserIDNotInList(t *testing.T) {
	peers := []api.Peer{{ID: "p1", IP: "100.99.1.2", UserID: "u99"}}
	users := []api.User{
		{ID: "u1", Email: "alice@example.com"},
	}
	srv := makeServer(t, peers, users)
	defer srv.Close()
	useServer(t, srv)

	result := Authorize("100.99.1.2", "alice", srv.Client())
	if result != pamDeny {
		t.Errorf("expected pamDeny when userID not in users list, got %d", result)
	}
}

func TestAuthorize_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(10 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	useServer(t, srv)

	client := &http.Client{Timeout: 100 * time.Millisecond}
	result := Authorize("100.99.1.2", "alice", client)
	if result != pamDeny {
		t.Errorf("expected pamDeny on timeout, got %d", result)
	}
}
