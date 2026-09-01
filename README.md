# netbird-pam

A PAM exec module that validates SSH logins against NetBird peer identity.
When a user connects via SSH from a NetBird IP, this binary fetches the
peer's associated NetBird user, derives a Unix username from their email,
and allows or denies accordingly.

## How it works

1. PAM calls this binary on auth
2. It reads `PAM_RHOST` (source IP) and `PAM_USER` (requested username)
3. If the IP is in the NetBird subnet, it queries the NetBird API to find
   the peer and its associated user
4. It derives a Unix username from the user's email (`foo.bar@x.com` → `foo-bar`)
5. If that matches `PAM_USER`, access is granted

## Building

```bash
go build \
  -ldflags="-X main.netbirdToken=YOUR_TOKEN \
            -X main.netbirdAPI=https://api.netbird.io \
            -X main.netbirdPrefix=100." \
  -o netbird-pam \
  .
```

For aarch64 (Raspberry Pi):
```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
  -ldflags="..." \
  -o netbird-pam-aarch64 \
  .
```

## PAM configuration

In `/etc/pam.d/login` (before `@include common-auth` or after, depending on intent):
```
auth required pam_exec.so /usr/local/bin/netbird-pam
```


## Variables (set via -ldflags)

| Variable | Description |
|---|---|
| `netbirdToken` | NetBird API token |
| `netbirdAPI` | API base URL, e.g. `https://api.netbird.io` |
| `netbirdPrefix` | IP prefix to match NetBird peers, e.g. `100.` |

## Releases

Pre-built binaries for `linux/amd64` and `linux/arm64` are available on the
[Releases](../../releases) page.