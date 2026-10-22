package guerrilla

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/flashmob/go-guerrilla/mail"
	"github.com/flashmob/go-guerrilla/tls"
)

func TestUpgradeToTLSRecordsHelloOnFailure(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		GetConfigForClient: recordClientHello,
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		defer clientConn.Close()
		_ = tls.Client(clientConn, &tls.Config{
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12,
			CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA},
		}).Handshake()
	}()

	c := &client{conn: serverConn}
	if err := c.upgradeToTLS(serverConfig); err == nil {
		t.Fatal("expected handshake to fail")
	}
	fields := c.tlsHelloFields()
	if got := fields["offered_ciphers"]; got != "0x0035" {
		t.Errorf("offered_ciphers = %v, want 0x0035", got)
	}
	if fields["offered_curves"] == "" {
		t.Error("offered_curves is empty")
	}
}

func TestTLSHelloFieldsWithoutHello(t *testing.T) {
	if fields := (&client{}).tlsHelloFields(); fields != nil {
		t.Errorf("tlsHelloFields() = %v, want nil", fields)
	}
}

// testCert returns a self-signed certificate using an RSA key of the given
// size, for use as a server or client certificate in the tests below.
func testCert(t *testing.T, bits int) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestUpgradeToTLSNegotiatesTLS13 verifies that a handshake negotiates TLS 1.3
// by default, without requiring GODEBUG=tls13=1.
func TestUpgradeToTLSNegotiatesTLS13(t *testing.T) {
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{testCert(t, 2048)},
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		defer clientConn.Close()
		cc := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
		if err := cc.Handshake(); err != nil {
			return
		}
		// Keep the connection open until the server side has read the state.
		var b [1]byte
		_, _ = cc.Read(b[:])
	}()

	c := &client{
		Envelope: mail.NewEnvelope("127.0.0.1", 1),
		conn:     serverConn,
		bufin:    newSMTPBufferedReader(serverConn),
		bufout:   bufio.NewWriter(serverConn),
	}
	if err := c.upgradeToTLS(serverConfig); err != nil {
		t.Fatalf("upgradeToTLS failed: %v", err)
	}
	stater, ok := c.conn.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		t.Fatal("upgraded conn does not expose ConnectionState")
	}
	if v := stater.ConnectionState().Version; v != tls.VersionTLS13 {
		t.Errorf("negotiated version = 0x%04x, want TLS 1.3 (0x%04x)", v, tls.VersionTLS13)
	}
}

// TestProcessClientCertRejectsLargeRSAKey verifies the backported DoS guard:
// a client certificate carrying an oversized RSA key is rejected rather than
// verified. The server uses VerifyClientCertIfGiven, so this path is reachable.
func TestProcessClientCertRejectsLargeRSAKey(t *testing.T) {
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{testCert(t, 2048)},
		ClientAuth:   tls.RequireAnyClientCert,
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		defer clientConn.Close()
		cc := tls.Client(clientConn, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{testCert(t, 9216)}, // > 8192-bit cap
		})
		_ = cc.Handshake()
	}()

	c := &client{conn: serverConn}
	if err := c.upgradeToTLS(serverConfig); err == nil {
		t.Fatal("expected handshake to fail for oversized client RSA key")
	}
}
