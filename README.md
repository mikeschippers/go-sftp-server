# Go SFTP Server

A lightweight, containerized SFTP server implementation written in Go. Don't use this in production!

## Features
- ED25519 Host Key: Automatically generates or loads an ED25519 host key
- Password Authentication: Simple username/password authentication
- Public Key Authentication: OpenSSH `authorized_keys` file support
- Docker Support: Ready-to-run Docker container
- Configurable: Command-line flags for easy configuration

> **Note:** At least one authentication method must be configured (`--pass` and/or `--authorized-keys`). The server will exit with an error if neither is provided.

## Usage

### Password authentication
```bash
docker build -t go-sftp-server .
docker run -d -p 2022:2022 --name sftp-server \
  go-sftp-server --user myuser --pass mysecret
```

### Public key authentication
```bash
docker run -d -p 2022:2022 --name sftp-server \
  -v ~/.ssh/authorized_keys:/keys/authorized_keys:ro \
  go-sftp-server --authorized-keys /keys/authorized_keys
```

### Both methods enabled
```bash
docker run -d -p 2022:2022 --name sftp-server \
  -v ~/.ssh/authorized_keys:/keys/authorized_keys:ro \
  go-sftp-server --user myuser --pass mysecret --authorized-keys /keys/authorized_keys
```

### Connect
```bash
# Password
sftp -P 2022 myuser@localhost

# Public key
sftp -i ~/.ssh/id_ed25519 -P 2022 myuser@localhost
```

## Configuration
The server accepts the following command-line flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `2022` | Port to listen on |
| `-hostkey` | `/keys/host_ed25519_key` | Path to host key file (auto-generated if missing) |
| `-user` | `testuser` | Username for authentication |
| `-pass` | *(empty)* | Password for authentication. Leave empty to disable password auth |
| `-authorized-keys` | *(empty)* | Path to OpenSSH `authorized_keys` file. Leave empty to disable public key auth |

### authorized_keys format
Standard OpenSSH format — one public key per line, blank lines and `#` comments are ignored:
```
# My laptop key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@laptop
ssh-rsa AAAAB3NzaC1yc2EAAAA... user@desktop
```