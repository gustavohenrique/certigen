package ocspresponder

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"certigen/src/shared/cryptus/certiman/ocspresponder/ocsp"
)

type Config struct {
	CaCert   string
	OcspCert string
	OcspKey  string
	Debug    bool
}

type Callback func(context.Context, *big.Int) (int, int, time.Time)

type Responder struct {
	config    *Config
	caCert    *x509.Certificate
	ocspCert  *x509.Certificate
	nonceList [][]byte
	callback  Callback
}

const (
	StatusValid   = 'V'
	StatusRevoked = 'R'
	StatusExpired = 'E'
	urlPathGET    = "/ocsp"
)

func NewResponder(config *Config) *Responder {
	return &Responder{
		config: config,
	}
}

func (h *Responder) MakeHttpHandler(callback Callback) func(w http.ResponseWriter, r *http.Request) {
	h.callback = callback
	if h.caCert == nil {
		caCert, err := parseCertFile(h.config.CaCert)
		if err != nil {
			log.Fatal(err)
		}
		h.caCert = caCert
	}
	if h.ocspCert == nil {
		ocspCert, err := parseCertFile(h.config.OcspCert)
		if err != nil {
			log.Fatal(err)
		}
		h.ocspCert = ocspCert
	}
	return func(w http.ResponseWriter, r *http.Request) {
		b := new(bytes.Buffer)
		switch r.Method {
		case "POST":
			b.ReadFrom(r.Body)
		case "GET":
			split := strings.Split(r.URL.Path, urlPathGET)
			encoded := split[len(split)-1]
			gd, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				h.log("Base64 error:", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r := bytes.NewReader(gd)
			b.ReadFrom(r)
		default:
			h.log("Unsupported request method")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		resp, err := h.verify(r.Context(), b.Bytes())
		if err != nil {
			h.log(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		h.log("Writing response ok")
		w.Write(resp)
	}
}

func (h *Responder) verify(ctx context.Context, rawreq []byte) ([]byte, error) {
	req, exts, err := ocsp.ParseRequest(rawreq)
	if err != nil {
		h.log(err)
		return nil, err
	}

	if err := h.verifyIssuer(req); err != nil {
		h.log(err)
		return nil, err
	}

	ocspKey, err := parseKeyFile(h.config.OcspKey)
	if err != nil {
		h.log("could not parse key file")
		return nil, err
	}
	key, ok := ocspKey.(crypto.Signer)
	if !ok {
		h.log("could not make a key signer")
		return nil, errors.New("Could not make key a signer")
	}

	var responseExtensions []pkix.Extension
	nonce := checkForNonceExtension(exts)

	if h.nonceList == nil {
		h.nonceList = make([][]byte, 10)
	}
	if nonce != nil {
		for _, n := range h.nonceList {
			if bytes.Compare(n, nonce.Value) == 0 {
				return nil, errors.New("This nonce has already been used")
			}
		}
		h.nonceList = append(h.nonceList, nonce.Value)
		responseExtensions = append(responseExtensions, *nonce)
	}

	now := time.Now()
	status, reason, revokedAt := h.callback(ctx, req.SerialNumber)
	template := ocsp.Response{
		Status:           status,
		RevocationReason: reason,
		SerialNumber:     req.SerialNumber,
		Certificate:      h.ocspCert,
		IssuerHash:       req.HashAlgorithm,
		RevokedAt:        revokedAt,
		ThisUpdate:       now.AddDate(0, 0, -1).UTC(),
		NextUpdate:       now.AddDate(0, 0, 1).UTC(),
		Extensions:       exts,
		ExtraExtensions:  responseExtensions,
	}
	resp, err := ocsp.CreateResponse(h.caCert, h.ocspCert, template, key)
	if err != nil {
		h.log("could not create ocsp response")
		return nil, err
	}
	return resp, err
}

func (h *Responder) verifyIssuer(req *ocsp.Request) error {
	alg := req.HashAlgorithm.New()
	alg.Write(h.caCert.RawSubject)
	if bytes.Compare(alg.Sum(nil), req.IssuerNameHash) != 0 {
		return errors.New("Issuer name does not match")
	}
	alg.Reset()
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(h.caCert.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return err
	}
	alg.Write(publicKeyInfo.PublicKey.RightAlign())
	if bytes.Compare(alg.Sum(nil), req.IssuerKeyHash) != 0 {
		return errors.New("Issuer key hash does not match")
	}
	return nil
}

func parseCertFile(filename string) (*x509.Certificate, error) {
	pubPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot parse %s cert", err)
	}
	block, _ := pem.Decode(pubPEM)
	return x509.ParseCertificate(block.Bytes)
}

func parseKeyFile(filename string) (interface{}, error) {
	var err error
	privPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot parse %s key", err)
	}
	block, _ := pem.Decode(privPEM)
	var key any
	key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	return key, err
}

func checkForNonceExtension(exts []pkix.Extension) *pkix.Extension {
	nonce_oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	for _, ext := range exts {
		if ext.Id.Equal(nonce_oid) {
			return &ext
		}
	}
	return nil
}

func (h *Responder) log(args ...interface{}) {
	if h.config.Debug {
		log.Println(args...)
	}
}
