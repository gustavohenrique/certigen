package certiman_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"certigen/src/shared/cryptus/certiman"
	"certigen/src/shared/testify/assert"
)

var tmpDir = os.TempDir()

func TestCertiman(t *testing.T) {
	config := certiman.NewConfig()
	expiresAt := time.Now().Add(time.Hour*time.Duration(0) +
		time.Minute*time.Duration(5) +
		time.Second*time.Duration(3))
	config.SetExpirationDate(expiresAt)
	config.SetCountry("br")
	config.SetLocality("rio de janeiro")
	config.SetOrganization("ravoni")
	config.SetCommonName("ca")
	config.SetIssuerName("Ravoni Labs")
	config.SetHosts([]string{"localhost"})

	var manager = certiman.New().With(config)

	// rootCA
	rootCA, err := manager.CreateRootCA()
	assert.Nil(t, err, ">>> CreateCA")
	assert.True(t, len(rootCA.PrivateKey) > 0)
	assert.True(t, len(rootCA.PublicKey) > 0)
	save(tmpDir, "ca.pem", rootCA.PublicKey)
	save(tmpDir, "ca.key", rootCA.PrivateKey)

	caTLS, err := manager.Parse(rootCA)
	assert.Nil(t, err, "Parse")
	assert.Equal(t, config.Organization(), caTLS.X509Certificate.Subject.Organization[0])
	assert.Equal(t, config.Country(), caTLS.X509Certificate.Subject.Country[0])
	assert.Equal(t, config.Locality(), caTLS.X509Certificate.Subject.Locality[0])
	assert.Equal(t, config.CommonName(), caTLS.X509Certificate.Subject.CommonName)
	assert.True(t, caTLS.X509Certificate.IsCA)

	// intermediate CA
	config.SetID("my-inter-uuid")
	config.SetCommonName("Intermediate CA")
	config.SetOrganizationalUnit("some-uuid")
	config.SetIssuerName("it should be ignored")
	intermediateCA, err := manager.CreateIntermediateCA(rootCA)
	assert.Nil(t, err, "CreateIntermediate")
	save(tmpDir, "inter.pem", intermediateCA.PublicKey)
	save(tmpDir, "inter.key", intermediateCA.PrivateKey)

	assert.NotEqual(t, intermediateCA.PrivateKey, rootCA.PrivateKey)
	assert.NotEqual(t, intermediateCA.PublicKey, rootCA.PublicKey)

	intermediateTLS, err := manager.Parse(intermediateCA)
	assert.Nil(t, err, "Parse intermediate")
	assert.Equal(t, config.CommonName(), intermediateTLS.X509Certificate.Subject.CommonName)
	assert.Equal(t, caTLS.X509Certificate.Subject.CommonName, intermediateTLS.X509Certificate.Issuer.CommonName)
	assert.Equal(t, config.OrganizationalUnit(), intermediateTLS.X509Certificate.Subject.OrganizationalUnit[0])
	assert.True(t, intermediateTLS.X509Certificate.IsCA)

	// server
	config.SetID("my-server-uuid")
	config.SetCommonName("payment-api")
	config.SetOrganization("Finance")
	config.SetOrganizationalUnit("TeamX")
	serverCert, err := manager.CreateServerCert(intermediateCA)
	assert.Nil(t, err, "CreateServerCert")
	save(tmpDir, "server.pem", serverCert.PublicKey)
	save(tmpDir, "server.key", serverCert.PrivateKey)

	serverTLS, err := manager.Parse(serverCert)
	assert.Nil(t, err, "Parse server cert")
	assert.Equal(t, config.CommonName(), serverTLS.X509Certificate.Subject.CommonName)
	assert.Equal(t, intermediateTLS.X509Certificate.Subject.CommonName, serverTLS.X509Certificate.Issuer.CommonName)
	assert.Equal(t, config.Organization(), serverTLS.X509Certificate.Subject.Organization[0])
	assert.Equal(t, config.OrganizationalUnit(), serverTLS.X509Certificate.Subject.OrganizationalUnit[0])
	assert.False(t, serverTLS.X509Certificate.IsCA)

	// client
	config.SetID("my-client-uuid")
	config.SetCommonName("bff")
	config.SetHosts([]string{"payment-api"})
	config.SetOrganization("Finance")
	config.SetOrganizationalUnit("TeamX")
	clientCert, err := manager.CreateClientCert(intermediateCA)
	assert.Nil(t, err, "CreateClientCert")
	save(tmpDir, "client.pem", clientCert.PublicKey)
	save(tmpDir, "client.key", clientCert.PrivateKey)

	clientTLS, err := manager.Parse(clientCert)
	assert.Nil(t, err, "Parse client cert")
	assert.Equal(t, config.CommonName(), clientTLS.X509Certificate.Subject.CommonName)
	assert.Equal(t, intermediateTLS.X509Certificate.Subject.CommonName, clientTLS.X509Certificate.Issuer.CommonName)
	assert.Equal(t, config.Organization(), clientTLS.X509Certificate.Subject.Organization[0])
	assert.Equal(t, config.OrganizationalUnit(), clientTLS.X509Certificate.Subject.OrganizationalUnit[0])
	assert.False(t, clientTLS.X509Certificate.IsCA)

	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM([]byte(intermediateCA.PublicKey)); !ok {
		t.Fatalf("failed to parse root certificate")
	}

	loadedServerCert := loadCerts("server.pem", "server.key")
	ln, err := tls.Listen("tcp", ":64321", &tls.Config{
		Certificates: []tls.Certificate{
			loadedServerCert,
		},
		ClientCAs: roots,
		// InsecureSkipVerify: true,
		ClientAuth: tls.RequireAndVerifyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			}
			// Needs load intermediate pubkey first
			opts.Roots.AddCert(intermediateTLS.X509Certificate)
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("bad cert: no peer certificates")
			}

			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
				return fmt.Errorf("failed to verify client certificate: %v", err)
			}
			//
			clientCertificate := cs.PeerCertificates[0]
			if clientCertificate.Equal(loadedServerCert.Leaf) {
				// It occours when the client is the server instance
				return nil
			}
			cn := serverTLS.X509Certificate.Subject.CommonName
			allow := clientCertificate.PermittedURIDomains
			if len(allow) == 0 || !slices.Contains(allow, cn) {
				return fmt.Errorf("certificate client cannot access %s. only access: %s", cn, allow)
			}
			log.Println(">>> Serial=", clientCertificate.SerialNumber)
			log.Println(">>> Subject.Serial=", clientCertificate.Subject.SerialNumber)
			log.Println(">>> PermittedURIDomains=", clientCertificate.PermittedURIDomains)
			return nil
		},
	})
	if err != nil {
		t.Errorf("failed to listen: %s", err)
	}
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				t.Errorf("failed to accept connection: %s", err)
				continue
			}
			defer conn.Close()
			conn.Write([]byte("Hello!"))
		}
	}()

	conn, err := tls.Dial("tcp", "localhost:64321", &tls.Config{
		Certificates: []tls.Certificate{
			loadCerts("client.pem", "client.key"),
		},
		RootCAs: roots,
		// InsecureSkipVerify: true,
	})
	if err != nil || conn == nil {
		t.Fatalf("cannot connect to server: %s", err)
	}
	defer conn.Close()

	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("failed to read: %s", err)
	}
	response := string(buffer[:n])
	assert.Equal(t, "Hello!", response)
}

func save(dir, file, content string) {
	filename := filepath.Join(dir, file)
	os.WriteFile(filename, []byte(content), 0644)
	fmt.Println(">>>>>", filename)
}

func loadCerts(pub, priv string) tls.Certificate {
	publicKey := filepath.Join(tmpDir, pub)
	privateKey := filepath.Join(tmpDir, priv)
	certificate, _ := tls.LoadX509KeyPair(publicKey, privateKey)
	return certificate
}
