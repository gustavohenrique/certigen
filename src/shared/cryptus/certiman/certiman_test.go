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

var tmpDir = "/tmp"

func TestCertiman(t *testing.T) {
	template := certiman.NewTemplate()
	expiresAt := time.Now().Add(time.Hour*time.Duration(48) +
		time.Minute*time.Duration(5) +
		time.Second*time.Duration(3))
	template.SetExpirationDate(expiresAt)
	template.AddCountry("br")
	template.AddLocality("rio de janeiro")
	template.AddOrganization("ravoni")
	template.SetCommonName("ca")
	template.SetIssuerName("Ravoni Labs")
	template.SetHosts([]string{"localhost"})

	var manager = certiman.New().With(template)

	// rootCA
	rootCA, err := manager.CreateRootCA()
	assert.Nil(t, err, ">>> CreateCA")
	assert.True(t, len(rootCA.PrivateKey) > 0)
	assert.True(t, len(rootCA.PublicKey) > 0)
	save(tmpDir, "ca.pem", rootCA.PublicKey)
	save(tmpDir, "ca.key", rootCA.PrivateKey)

	caTLS, err := manager.Parse(rootCA)
	assert.Nil(t, err, "Parse")
	assert.Equal(t, template.Organizations()[0], caTLS.X509Certificate.Subject.Organization[0])
	assert.Equal(t, template.Countries()[0], caTLS.X509Certificate.Subject.Country[0])
	assert.Equal(t, template.Localities()[0], caTLS.X509Certificate.Subject.Locality[0])
	assert.Equal(t, template.CommonName(), caTLS.X509Certificate.Subject.CommonName)
	assert.True(t, caTLS.X509Certificate.IsCA)

	// intermediate CA
	template.SetID("my-inter-uuid")
	template.SetCommonName("Intermediate CA")
	template.SetOrganizationalUnits([]string{"some-uuid"})
	template.SetIssuerName("it should be ignored")
	intermediateCA, err := manager.WithKeyPair(rootCA.PublicKey, rootCA.PrivateKey).CreateIntermediateCA()
	assert.Nil(t, err, "CreateIntermediate")
	save(tmpDir, "inter.pem", intermediateCA.PublicKey)
	save(tmpDir, "inter.key", intermediateCA.PrivateKey)

	assert.NotEqual(t, intermediateCA.PrivateKey, rootCA.PrivateKey)
	assert.NotEqual(t, intermediateCA.PublicKey, rootCA.PublicKey)

	intermediateTLS, err := manager.Parse(intermediateCA)
	assert.Nil(t, err, "Parse intermediate")
	assert.Equal(t, template.CommonName(), intermediateTLS.X509Certificate.Subject.CommonName)
	assert.Equal(t, caTLS.X509Certificate.Subject.CommonName, intermediateTLS.X509Certificate.Issuer.CommonName)
	assert.Equal(t, template.OrganizationalUnits()[0], intermediateTLS.X509Certificate.Subject.OrganizationalUnit[0])
	assert.True(t, intermediateTLS.X509Certificate.IsCA)

	// server
	template.SetID("my-server-uuid")
	template.SetCommonName("payment-api")
	template.SetOrganizations([]string{"Finance"})
	template.SetOrganizationalUnits([]string{"TeamX"})
	template.SetOcspURL("http://localhost:8002/ocsp")
	serverCert, err := manager.WithKeyPair(intermediateCA.PublicKey, intermediateCA.PrivateKey).CreateServerCert()
	assert.Nil(t, err, "CreateServerCert")
	save(tmpDir, "server.pem", serverCert.PublicKey)
	save(tmpDir, "server.key", serverCert.PrivateKey)

	serverTLS, err := manager.Parse(serverCert)
	assert.Nil(t, err, "Parse server cert")
	assert.Equal(t, template.CommonName(), serverTLS.X509Certificate.Subject.CommonName)
	assert.Equal(t, intermediateTLS.X509Certificate.Subject.CommonName, serverTLS.X509Certificate.Issuer.CommonName)
	assert.Equal(t, template.Organizations()[0], serverTLS.X509Certificate.Subject.Organization[0])
	assert.Equal(t, template.OrganizationalUnits()[0], serverTLS.X509Certificate.Subject.OrganizationalUnit[0])
	assert.False(t, serverTLS.X509Certificate.IsCA)

	// oscp
	template.SetID("ocsp-server")
	template.SetCommonName("ocsp")
	template.SetOrganizations([]string{"Finance"})
	template.SetOrganizationalUnits([]string{"TeamX"})
	ocspCert, err := manager.WithKeyPair(intermediateCA.PublicKey, intermediateCA.PrivateKey).CreateServerCert()
	assert.Nil(t, err, "CreateOCSP")
	save(tmpDir, "ocsp.pem", ocspCert.PublicKey)
	save(tmpDir, "ocsp.key", ocspCert.PrivateKey)

	// client
	template.SetID("my-client-uuid")
	template.SetCommonName("bff")
	template.SetPermittedUriDomains([]string{"payment-api"})
	template.SetOrganizations([]string{"Finance"})
	template.SetOrganizationalUnits([]string{"TeamX"})
	template.SetOcspURL("http://localhost:8002/ocsp")
	clientCert, err := manager.WithKeyPair(intermediateCA.PublicKey, intermediateCA.PrivateKey).CreateClientCert()
	assert.Nil(t, err, "CreateClientCert")
	save(tmpDir, "client.pem", clientCert.PublicKey)
	save(tmpDir, "client.key", clientCert.PrivateKey)

	clientTLS, err := manager.Parse(clientCert)
	assert.Nil(t, err, "Parse client cert")
	assert.Equal(t, template.CommonName(), clientTLS.X509Certificate.Subject.CommonName)
	assert.Equal(t, intermediateTLS.X509Certificate.Subject.CommonName, clientTLS.X509Certificate.Issuer.CommonName)
	assert.Equal(t, template.PermittedUriDomains()[0], clientTLS.X509Certificate.PermittedURIDomains[0])
	assert.Equal(t, template.Organizations()[0], clientTLS.X509Certificate.Subject.Organization[0])
	assert.Equal(t, template.OrganizationalUnits()[0], clientTLS.X509Certificate.Subject.OrganizationalUnit[0])
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
		// defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				t.Errorf("failed to accept connection: %s", err)
				continue
			}
			// defer conn.Close()
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
