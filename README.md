# go-data-server

A small key-value/blob store that several projects can share. Go, standard library only.

- Every app gets its own **token** and its own **key space**: `/api/{app}/{key...}`.
- Any content type. Optimistic concurrency with `ETag` / `If-Match`.
- **HTTPS without a domain**: it serves the Let's Encrypt certificate for the VPS's IP address
  (obtained and renewed by [lego](https://go-acme.github.io/lego/)) and reloads it when it changes.
- A **web UI** at `/ui` to browse, sort, download, upload and delete files, with a storage panel
  (disk free/used, and what the apps have stored) for the admin. It is only reachable from networks you
  allow (for example your VPN).

## API

All `/api/{app}/…` routes need `Authorization: Bearer <token>` for that app.

| Method | Path | |
|---|---|---|
| GET | `/healthz` | no auth, `{"status":"ok"}` |
| GET | `/api/whoami` | who the token belongs to, which apps it sees, the upload limit |
| GET | `/api/system` | **admin only**: `{"disk":{"free","total"}|null,"stored_bytes","stored_files"}` — free and total space of the disk holding `DATA_DIR`, and what all apps have stored |
| GET | `/api/{app}?prefix=` | list: `[{"key","size","content_type","etag","modified"}]` |
| GET / HEAD | `/api/{app}/{key...}` | the blob with its `Content-Type`, `ETag`, `Last-Modified`; supports `If-None-Match` and `Range`; `?download=1` adds `Content-Disposition: attachment` |
| PUT | `/api/{app}/{key...}` | store the body (any content type). `If-None-Match: *` = create only, `If-Match: <etag>` = replace only that version. 201 created, 200 replaced, 412 if a precondition fails |
| DELETE | `/api/{app}/{key...}` | 204, or 404. Honours `If-Match` |

Keys are `/`-separated segments of letters, digits, `.`, `_`, `-` (max 512 characters, no `.` or `..`
segment). App names are `a-z`, `0-9`, `-`; `whoami` and `system` are reserved. Uploads are limited to `DATA_MAX_BODY` (413 above that).

```bash
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -X PUT --data @progress.json https://<IP>:9696/api/myapp/progress.json
curl -H "Authorization: Bearer $TOKEN" https://<IP>:9696/api/myapp/progress.json
```

Safe update: `GET`, remember the `ETag`, then `PUT` with `If-Match: <etag>`. A 412 means someone
else changed it first; fetch again and retry.

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `DATA_ADDR` | `127.0.0.1:9696` | listen address (`0.0.0.0:9696` on the VPS) |
| `DATA_DIR` | `./data` | where blobs are stored |
| `DATA_APPS_FILE` | `./apps` | the token file (see below) |
| `DATA_TLS_CERT`, `DATA_TLS_KEY` | — | certificate chain and key (PEM). If set, the server speaks HTTPS and reloads them when they change |
| `DATA_MAX_BODY` | `52428800` | largest upload in bytes (50 MiB) |
| `DATA_UI` | `1` | `0` turns the web UI off completely |
| `DATA_UI_ALLOW_CIDR` | `127.0.0.0/8,::1/128` | networks allowed to use the UI **and the `_admin` token**, comma-separated. Default: this machine only |
| `DATA_ALLOW_INSECURE` | — | `1` allows plain HTTP on a non-loopback address. Without it the server refuses to start that way, so tokens can't cross the network unencrypted |

### Tokens

`apps` holds one line per app: `<app> <sha256 of its token>` (see `deploy/apps.example`). Only hashes
are stored. Create a token and its line with:

```bash
./go-data-server newtoken myapp
./go-data-server newtoken _admin     # the web UI token
```

`systemctl reload go-data-server` (SIGHUP) re-reads the file; a broken file is rejected and the old
tokens stay active.

`_admin` can use every app, but **only from `DATA_UI_ALLOW_CIDR`**: from anywhere else it is treated
as a wrong token. App tokens work from anywhere.

## Build

On Windows (produces `dist\go-data-server-linux-amd64`, change `$arch` in the script for ARM):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
```

Develop:

```powershell
$env:GOCACHE = "$PWD\.cache\go-build"
go vet ./... ; go test ./...
```

Run locally (plain HTTP on loopback is allowed):

```powershell
go run . newtoken _admin      # copy the printed line into a file named "apps"
go run .                      # then open http://127.0.0.1:9696/ui
```

## Deploy on the VPS

Replace `<IP>` with the VPS's static public IP. Ports 80 (certificate checks) and 9696 (the API) must be
open in the firewall, and nothing else may listen on port 80.

**1. Install the binary and helper** (from your PC, then on the VPS):

```bash
scp dist/go-data-server-linux-amd64 deploy/lego-deploy-hook.sh deploy/go-data-server.service root@<IP>:/root/
```
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin data
sudo install -d -m 755 /opt/go-data-server /etc/go-data-server
sudo install -m 755 go-data-server-linux-amd64 /opt/go-data-server/go-data-server
sudo install -m 755 lego-deploy-hook.sh /opt/go-data-server/lego-deploy-hook.sh
sudo cp go-data-server.service /etc/systemd/system/
```

**2. Create tokens** and put the printed lines in `/etc/go-data-server/apps`:

```bash
/opt/go-data-server/go-data-server newtoken _admin
/opt/go-data-server/go-data-server newtoken myapp
sudoedit /etc/go-data-server/apps
sudo chown root:data /etc/go-data-server/apps && sudo chmod 640 /etc/go-data-server/apps
```

**3. Get the certificate** with lego v5. An IP certificate needs the `shortlived` profile (valid about
6.5 days, so it must renew automatically). Try the Let's Encrypt staging server first:

```bash
sudo lego run -s letsencrypt-staging -a -d <IP> --http --profile shortlived --path /etc/lego-staging
```
```bash
sudo lego run -a -d <IP> --http --profile shortlived --path /etc/lego
sudo /opt/go-data-server/lego-deploy-hook.sh <IP>
```

The hook copies `/etc/lego/certificates/<IP>.crt|key` to `/etc/go-data-server/tls/` for the service user.

**4. Renew automatically.** `lego run` renews when about half the lifetime is left, so run it twice a day.
The hook is idempotent and the server only reloads when the content changed:

```bash
echo '17 3,15 * * * root /usr/local/bin/lego run -a -d <IP> --http --profile shortlived --path /etc/lego >> /var/log/lego.log 2>&1 && /opt/go-data-server/lego-deploy-hook.sh <IP>' | sudo tee /etc/cron.d/lego
```

**5. Configure and start:**

```bash
sudo tee /etc/go-data-server.env <<'EOF'
DATA_ADDR=0.0.0.0:9696
DATA_TLS_CERT=/etc/go-data-server/tls/cert.pem
DATA_TLS_KEY=/etc/go-data-server/tls/key.pem
DATA_UI_ALLOW_CIDR=127.0.0.0/8,::1/128
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now go-data-server
sudo ufw allow 9696/tcp
journalctl -u go-data-server -n 20
curl https://<IP>:9696/healthz     # must work without -k
```

When the renewal works, the log shows `certificate reloaded` a few days apart. If the certificate has
less than 48 h left, the log shows a `WARNING` line.

### Web UI from your VPN only

AmneziaWG runs on the host as interface `awg0`. Its clients reach the server from addresses inside that
interface's networks, so allow those networks:

```bash
ip -br addr show awg0        # e.g. 10.8.1.1/24 and an IPv6 /64
```

Add the **network** (host bits zeroed: `10.8.1.1/24` → `10.8.1.0/24`) to `DATA_UI_ALLOW_CIDR` in
`/etc/go-data-server.env`, then `sudo systemctl restart go-data-server`.

With the VPN connected, open the server's **VPN-side address** (the `awg0` IPv4 address from the command
above, without the `/24`, e.g. `https://10.8.1.1:9696/ui`) and sign in with the `_admin` token. Do **not**
use the public IP: VPN clients keep the VPS's public address outside the tunnel, so the server would see
your real home/mobile address and refuse the UI.

The browser warns about the certificate on that address, because the Let's Encrypt certificate is only
valid for the public IP (and Let's Encrypt can't issue certificates for private addresses). That is
expected: accept the exception once (Firefox: Advanced, Accept the Risk and Continue; it remembers it
for that address and port). The connection is still encrypted by the VPN tunnel itself.

From any other address `/ui` answers 404 and the journal shows `ui denied from <address>`, which also
tells you which address to allow if a network was missed. Loopback is allowed by default, so
`ssh -L 9696:127.0.0.1:9696 <vps>` works as a fallback (use `-k`/accept the warning, the certificate is
for the IP).

### Web UI notes

The token lives in the browser tab's `sessionStorage` until you log out or close the tab. Downloaded
and previewed files are served with `Content-Security-Policy: sandbox` and `nosniff`, so an uploaded
HTML or SVG file cannot run script against this server.

## Migrating nastaunik's saves-server

`PUT /api/progress` becomes `PUT /api/nastaunik/progress.json` with `Content-Type: application/json`.
The old "newest `updated_at` wins" rule becomes `If-Match: <etag>`: `GET` the file, keep the `ETag`,
`PUT` with `If-Match`; on 412 fetch the stored copy and decide in the app. The old server stays as it
is until the app is changed.

## Limits worth knowing

- The certificate is for the IP: if the VPS IP changes you must issue a new one.
- Metadata and blobs are separate files; a crash between the two writes of one upload can leave a blob
  with the previous version's metadata (size/ETag). Re-uploading fixes it.
- One process, one directory, no replication. Back up `DATA_DIR`.
- Failed-login rate limiting is not implemented: tokens are 256-bit random, so guessing isn't practical.
