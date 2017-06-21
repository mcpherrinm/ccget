package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func main() {
	err := do()
	if err != nil {
		log.Fatal("Error", err)
	}
}

var ciphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

func do() error {
	args := os.Args[1:]
	if len(args) != 4 {
		fmt.Printf("Usage: ccget cert key cabundle url\n")
		return nil
	}
	certFile := args[0]
	keyFile := args[1]
	caFile := args[2]
	url := args[3]
	keyPair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("Error loading keypair: cert %s, key %s: %v", certFile, keyFile, err)
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("Error loading CA file '%s': %v", caFile, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	config := &tls.Config{
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &keyPair, nil
		},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12, // TLSv1.2 and up is required
		CipherSuites: ciphers,
	}
	config.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: config}
	client := http.Client{Transport: transport}

	resp, err := client.Get(url)
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	if err != nil {
		return fmt.Errorf("Error writing stdout %v", err)
	}

	return nil
}
