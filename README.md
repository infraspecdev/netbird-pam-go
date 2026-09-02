# netbird-pam

A PAM exec module that validates SSH logins against NetBird peer identity.

NetBird's built-in SSH server does not use OpenSSH, it runs its own embedded Go SSH server and spawns sessions via the system `login` binary, which means auth goes through `/etc/pam.d/login`, not `/etc/pam.d/sshd`.
This module hooks into that flow to validate that the connecting peer's NetBird identity matches the requested Unix username.

Non-NetBird logins are passed through untouched without any API calls.

## How it works

1. A user connects via `netbird ssh` or the NetBird SSH client
2. NetBird's SSH server calls `login -f <username> -h <peer_ip>`, which
   triggers the `/etc/pam.d/login` PAM stack
3. This binary reads `PAM_RHOST` (source IP) and `PAM_USER` (requested username)
4. If the IP is outside the configured NetBird subnet, it exits successfully
   and lets the rest of the PAM stack proceed normally
5. Otherwise it reads `/etc/netbird-pam/config.env` and queries the NetBird
   API to find the peer and its associated user
6. It derives a Unix username from the user's email (`foo.bar@example.com` → `foo-bar`)
7. If that matches `PAM_USER`, access is granted, otherwise it is denied

## Configuration

Create `/etc/netbird-pam/config.env` (root-readable only):

```bash
NETBIRD_PAM_TOKEN=your-api-token
NETBIRD_PAM_API_URL=https://api.netbird.io
NETBIRD_PAM_IP_PREFIX=100.
```

```bash
sudo mkdir -p /etc/netbird-pam
sudo chmod 600 /etc/netbird-pam/config.env
sudo chown -R root:root /etc/netbird-pam
```

| Variable | Description |
|---|---|
| `NETBIRD_PAM_TOKEN` | NetBird API token |
| `NETBIRD_PAM_API_URL` | API base URL, e.g. `https://api.netbird.io` |
| `NETBIRD_PAM_IP_PREFIX` | IP prefix to match NetBird peers, e.g. `100.` |

## Building

```bash
CGO_ENABLED=0 go build -o netbird-pam .
```

Cross-compilation:

```bash
# amd64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o netbird-pam-x86_64 .

# arm64 (e.g. Raspberry Pi)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o netbird-pam-aarch64 .
```

## Installation

```bash
sudo cp netbird-pam-x86_64 /usr/local/lib/netbird-pam
sudo chown root:root /usr/local/lib/netbird-pam
sudo chmod 755 /usr/local/lib/netbird-pam
```

## PAM configuration

Add to `/etc/pam.d/login` **before** `@include common-auth`:

```
auth required pam_exec.so /usr/local/lib/netbird-pam
```


Logs are written to syslog under the `netbird-pam` tag and appear in `journalctl -t netbird-pam`.

## Releases

Pre-built binaries for `linux/amd64` and `linux/arm64` are available on the [Releases](../../releases) page.