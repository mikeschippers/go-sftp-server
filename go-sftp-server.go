package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	port               = flag.Int("port", 2022, "Port to listen on")
	hostKeyPath        = flag.String("hostkey", "/keys/host_ed25519_key", "Path to host key file")
	username           = flag.String("user", "testuser", "Username for authentication")
	password           = flag.String("pass", "", "Password for authentication (leave empty to disable password auth)")
	authorizedKeysPath = flag.String("authorized-keys", "", "Path to authorized_keys file (leave empty to disable public key auth)")
)

func main() {
	flag.Parse()

	hostKey, err := loadOrGenerateHostKey(*hostKeyPath)
	if err != nil {
		log.Fatalf("Failed to load or generate host key: %v", err)
	}

	// Load authorized keys if path is provided
	var authorizedKeys []ssh.PublicKey
	if *authorizedKeysPath != "" {
		authorizedKeys, err = loadAuthorizedKeys(*authorizedKeysPath)
		if err != nil {
			log.Fatalf("Failed to load authorized keys: %v", err)
		}
	}

	passwordAuthEnabled := *password != ""
	pubKeyAuthEnabled := len(authorizedKeys) > 0

	if !passwordAuthEnabled && !pubKeyAuthEnabled {
		log.Fatalf("No authentication method available: provide --pass and/or a valid --authorized-keys file")
	}

	config := &ssh.ServerConfig{}

	if passwordAuthEnabled {
		config.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == *username && string(pass) == *password {
				log.Printf("User %s authenticated via password from %s", c.User(), c.RemoteAddr())
				return nil, nil
			}
			log.Printf("Failed password authentication attempt for user %s from %s", c.User(), c.RemoteAddr())
			return nil, fmt.Errorf("password rejected for %q", c.User())
		}
	}

	if pubKeyAuthEnabled {
		config.PublicKeyCallback = func(c ssh.ConnMetadata, offered ssh.PublicKey) (*ssh.Permissions, error) {
			for _, stored := range authorizedKeys {
				if bytes.Equal(stored.Marshal(), offered.Marshal()) {
					log.Printf("User %s authenticated via public key (%s) from %s", c.User(), ssh.FingerprintSHA256(offered), c.RemoteAddr())
					return nil, nil
				}
			}
			log.Printf("Failed public key authentication attempt for user %s from %s (key: %s)", c.User(), c.RemoteAddr(), ssh.FingerprintSHA256(offered))
			return nil, fmt.Errorf("public key rejected for %q", c.User())
		}
	}

	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SFTP server listening on port %d", *port)
	log.Printf("Username: %s", *username)
	log.Printf("Auth methods: password=%v, publickey=%v", passwordAuthEnabled, pubKeyAuthEnabled)
	if pubKeyAuthEnabled {
		log.Printf("Loaded %d authorized public key(s) from %s", len(authorizedKeys), *authorizedKeysPath)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn, config)
	}
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	log.Printf("New connection from %s", conn.RemoteAddr())

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed to handshake with %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer sshConn.Close()

	log.Printf("SSH connection established from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {

		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", newChannel.ChannelType()))
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}

		go handleChannelRequests(channel, requests)
	}
}

func handleChannelRequests(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "subsystem":

			if len(req.Payload) < 4 {
				req.Reply(false, nil)
				continue
			}
			subsystem := string(req.Payload[4:])

			if subsystem == "sftp" {
				req.Reply(true, nil)
				log.Printf("Starting SFTP subsystem")
				handleSFTP(channel)
				return
			}
			req.Reply(false, nil)

		default:
			req.Reply(false, nil)
		}
	}
}

func handleSFTP(channel ssh.Channel) {

	server, err := sftp.NewServer(channel)
	if err != nil {
		log.Printf("Failed to create SFTP server: %v", err)
		return
	}
	defer server.Close()

	log.Printf("SFTP session started")

	if err := server.Serve(); err != nil && err != io.EOF {
		log.Printf("SFTP server error: %v", err)
	}

	log.Printf("SFTP session ended")
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {

	if _, err := os.Stat(path); err == nil {
		log.Printf("Loading existing host key from %s", path)
		return loadHostKey(path)
	}

	log.Printf("Generating new ED25519 host key at %s", path)
	return generateAndSaveHostKey(path)
}

func loadHostKey(path string) (ssh.Signer, error) {
	privateBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read host key: %v", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host key: %v", err)
	}

	return private, nil
}

func generateAndSaveHostKey(path string) (ssh.Signer, error) {

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	privatePem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	})

	if err := ioutil.WriteFile(path, privatePem, 0600); err != nil {
		return nil, fmt.Errorf("failed to write host key: %v", err)
	}

	log.Printf("Host key saved to %s", path)

	signer, err := ssh.ParsePrivateKey(privatePem)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated key: %v", err)
	}

	return signer, nil
}

func loadAuthorizedKeys(path string) ([]ssh.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open authorized_keys file: %v", err)
	}
	defer f.Close()

	var keys []ssh.PublicKey
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		// Skip empty lines and comments
		if len(bytes.TrimSpace(line)) == 0 || bytes.HasPrefix(bytes.TrimSpace(line), []byte("#")) {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			log.Printf("Warning: skipping invalid key on line %d of %s: %v", lineNum, path, err)
			continue
		}
		keys = append(keys, pub)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading authorized_keys file: %v", err)
	}
	return keys, nil
}

