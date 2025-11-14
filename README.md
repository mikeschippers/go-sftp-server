# Go SFTP Server

A lightweight, containerized SFTP server implementation written in Go. Dont use this in production!

## Features
- ED25519 Host Key: Automatically generates or loads an ED25519 host key
- Password Authentication: Simple username/password authentication
- Docker Support: Ready-to-run Docker container
- Configurable: Command-line flags for easy configuration

## Usage
1. Build the Docker image:
2. ```bash
   docker build -t go-sftp-server .
   ```
3. Run the Docker container:
4. ```bash
   docker run -d -p 2022:2022 --name sftp-server go-sftp-server
   ```
5. Connect to the SFTP server using an SFTP client:
6. ```bash
   sftp -P 2022 testuser@localhost
   ```

## Configuration
The server accepts the following command-line flags:
-port: Port to listen on (default: 2022)
-hostkey: Path to host key file (default: /keys/host_ed25519_key)
-user: Username for authentication (default: testuser)
-pass: Password for authentication (default: testpass)
-debug: Enable debug output (default: false)