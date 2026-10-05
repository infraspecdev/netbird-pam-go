# netbird-pam

A PAM exec module that validates SSH logins against NetBird peer identity.

NetBird's built-in SSH server does not use OpenSSH, it runs its own embedded Go SSH server and spawns sessions via the system `login` binary, which means auth goes through `/etc/pam.d/login` (or `/etc/pam.d/remote`, see [PAM configuration](#pam-configuration)), not `/etc/pam.d/sshd`.
This module hooks into that flow to validate that the connecting peer's NetBird identity matches the requested Unix username.

Non-NetBird logins are passed through untouched without any API calls.

## How it works

1. A user connects via `netbird ssh` or the NetBird SSH client
2. NetBird's SSH server calls `login -f <username> -h <peer_ip>`, which
   triggers the `/etc/pam.d/login` or `/etc/pam.d/remote` PAM stack,
   depending on the distro
3. This binary reads `PAM_RHOST` (source IP) and `PAM_USER` (requested username)
4. If the IP is outside the NetBird ranges (`100.99.` or
   `fdc1:f44a:39d9:c331:`, hardcoded in `main.go`), it exits successfully
   and lets the rest of the PAM stack proceed normally
5. Otherwise it reads `/etc/netbird-pam/config.env` and queries the NetBird
   API to find the peer and its associated user
6. It derives a Unix username from the user's email (`foo.bar@example.com` → `foo-bar`)
7. If that matches `PAM_USER`, access is granted, otherwise it is denied

## Configuration

Create `/etc/netbird-pam/config.env` (root-readable only):

```bash
NETBIRD_TOKEN=your-api-token
NETBIRD_MANAGEMENT_URL=https://netbird.example.com
```

```bash
sudo mkdir -p /etc/netbird-pam
sudo chmod 600 /etc/netbird-pam/config.env
sudo chown -R root:root /etc/netbird-pam
```

| Variable | Description |
|---|---|
| `NETBIRD_TOKEN` | NetBird personal access token (sent as `Authorization: Token <token>`) |
| `NETBIRD_MANAGEMENT_URL` | Management API base URL, no trailing slash, e.g. `https://api.netbird.io` |

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

NetBird runs `login -f`, which skips the `auth` stack, so the module hooks
into `account`. Add this line **before** `@include common-account`:

```
account required pam_exec.so /usr/local/lib/netbird-pam
```

Which file it goes in depends on which `login` the host ships, because
NetBird always passes `-h <peer_ip>`:

| Distro | `login` from | PAM service for `login -h` |
|---|---|---|
| Ubuntu 24.04 and older, Debian 12 and older | shadow | `/etc/pam.d/login` |
| Ubuntu 26.04+, Debian 13+ | util-linux | `/etc/pam.d/remote` |

Add the line to `/etc/pam.d/login`, and also to `/etc/pam.d/remote` if that
file exists. Local console logins still use `/etc/pam.d/login`; they have no
`PAM_RHOST`, so the module lets them through.

To see which service a NetBird session used, check
`journalctl | grep pam_unix` for `pam_unix(login:session)` or
`pam_unix(remote:session)`.

Logs are written to syslog under the `netbird-pam` tag and appear in `journalctl -t netbird-pam`.

## Troubleshooting

Each decision is logged as `allowing|denying: sourceIP=... requestedUser=... reason=...`.

| Reason | Meaning | Fix |
|---|---|---|
| `config-load-failed` | `config.env` is missing, or a variable is unset | Check the file and variable names above |
| `netbird-api-unauthorized` | The API returned 401: the token was rejected | Token is expired, revoked, mistyped, or from a different management server. Create a new one |
| `netbird-api-forbidden` | The API returned 403: the token is valid but its role can't read peers or users | Give the token's user a role that can read Peers and Users, e.g. Auditor |
| `netbird-api-failed` | Network error, timeout, or another non-200 status | Check `NETBIRD_MANAGEMENT_URL` and reachability from the host |
| `no-peer-found` | The API answered, but no peer has this IP | Peer was deleted, or the token's role can only see some peers |
| `peer-has-no-user-id` | The peer was added with a setup key, not by a user | Log in to NetBird as a user on the client device |
| `username-mismatch` | The peer's owner doesn't map to the requested username | Connect as the username derived from your email |

If NetBird SSH logins succeed but produce **no** `netbird-pam` log line at
all, the module isn't in the PAM service `login` is using. On Ubuntu 26.04+
and Debian 13+ that's `/etc/pam.d/remote`; see [PAM configuration](#pam-configuration).


## Releases

Pre-built binaries for `linux/amd64` and `linux/arm64` are available on the [Releases](../../releases) page.