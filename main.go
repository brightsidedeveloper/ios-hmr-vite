package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/go-chi/chi"
)

const ViteServerURL = "http://localhost:5173"

func GetLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatalf("Error getting local IP: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func generateSelfSignedCert(localIP string) (certPem, keyPem []byte, err error) {
	// Use a cryptographically secure random source
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Local Development"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP(localIP)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode the certificate
	certPemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPem = pem.EncodeToMemory(certPemBlock)

	// Encode the private key
	keyPemBlock, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPem = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPemBlock})

	return certPem, keyPem, nil
}

func main() {
	localIP := GetLocalIP()

	router := chi.NewRouter()

	proxyURL, err := url.Parse(ViteServerURL)
	if err != nil {
		log.Fatalf("Invalid VITE_SERVER_URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(proxyURL)

	router.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Host = proxyURL.Host
		r.URL.Scheme = proxyURL.Scheme
		r.Host = proxyURL.Host
		proxy.ServeHTTP(w, r)
	})

	// Generate certificates dynamically
	certPem, keyPem, err := generateSelfSignedCert(localIP)
	if err != nil {
		log.Fatalf("Error generating self-signed certificate: %v", err)
	}

	// Write certificates to temporary files
	tempDir := os.TempDir()
	certFile := tempDir + "/cert.pem"
	keyFile := tempDir + "/key.pem"
	err = os.WriteFile(certFile, certPem, 0600)
	if err != nil {
		log.Fatalf("Error writing temp cert file: %v", err)
	}
	err = os.WriteFile(keyFile, keyPem, 0600)
	if err != nil {
		log.Fatalf("Error writing temp key file: %v", err)
	}
	defer func() {
		_ = os.Remove(certFile)
		_ = os.Remove(keyFile)
	}()

	log.Printf("Server running on https://%s:3000", localIP)
	if err := http.ListenAndServeTLS(":3000", certFile, keyFile, router); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
