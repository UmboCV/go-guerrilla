package guerrilla

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

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
