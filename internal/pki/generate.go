package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

type RootRequest struct {
	CommonName   string
	KeyType      string
	Curve        string
	RSABits      string
	ValidityDays int
}

type RootResult struct {
	ID      string
	CertPEM []byte
	KeyPEM  []byte
}

type IntermediateRequest struct {
	CommonName   string
	IssuerCert   *x509.Certificate
	IssuerKey    crypto.Signer
	KeyType      string
	Curve        string
	RSABits      string
	ValidityDays int
}

type IntermediateResult struct {
	ID      string
	CertPEM []byte
	KeyPEM  []byte
}

type LeafRequest struct {
	CommonName   string
	DNSSANs      []string
	IPSANs       []net.IP
	IssuerCert   *x509.Certificate
	IssuerKey    crypto.Signer
	KeyType      string
	Curve        string
	RSABits      string
	ValidityDays int
}

type LeafResult struct {
	ID      string
	CertPEM []byte
	KeyPEM  []byte
}

func GenerateRootCA(req RootRequest) (*RootResult, error) {
	if req.CommonName == "" {
		return nil, fmt.Errorf("common name is required")
	}

	keyType := strings.ToLower(strings.TrimSpace(req.KeyType))
	if keyType == "" {
		keyType = "ecdsa"
	}

	var (
		privateKey crypto.Signer
		publicKey  crypto.PublicKey
		err        error
	)

	switch keyType {
	case "ecdsa":
		curve := normalizeCurveName(req.Curve)

		switch curve {
		case "p256":
			privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "p384":
			privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case "p521":
			privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			return nil, fmt.Errorf("invalid ECDSA curve")
		}
		if err != nil {
			return nil, fmt.Errorf("generate root key: %w", err)
		}

	case "rsa":
		bits, err := normalizeRSABits(req.RSABits)
		if err != nil {
			return nil, err
		}

		privateKey, err = rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("generate root key: %w", err)
		}

	default:
		return nil, fmt.Errorf("invalid key type")
	}

	publicKey = privateKey.Public()

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate root serial: %w", err)
	}

	now := time.Now().UTC()

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = 3650
	}

	ski, err := subjectKeyID(publicKey)
	if err != nil {
		return nil, fmt.Errorf("derive root subject key id: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: req.CommonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		SubjectKeyId:          ski,
		AuthorityKeyId:        ski,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create root certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})

	keyPEM, err := marshalPrivateKeyPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal root key: %w", err)
	}

	return &RootResult{
		ID:      makeID(req.CommonName),
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

func GenerateIntermediateCA(req IntermediateRequest) (*IntermediateResult, error) {
	if req.CommonName == "" {
		return nil, fmt.Errorf("common name is required")
	}
	if req.IssuerCert == nil {
		return nil, fmt.Errorf("issuer certificate is required")
	}
	if req.IssuerKey == nil {
		return nil, fmt.Errorf("issuer key is required")
	}
	if !req.IssuerCert.IsCA {
		return nil, fmt.Errorf("issuer certificate is not a CA")
	}
	if !isSelfSigned(req.IssuerCert) {
		return nil, fmt.Errorf("issuer certificate must be a root CA")
	}

	keyType := strings.ToLower(strings.TrimSpace(req.KeyType))
	if keyType == "" {
		keyType = "ecdsa"
	}

	var (
		privateKey crypto.Signer
		publicKey  crypto.PublicKey
		err        error
	)

	switch keyType {
	case "ecdsa":
		curve := normalizeCurveName(req.Curve)

		switch curve {
		case "p256":
			privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "p384":
			privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case "p521":
			privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			return nil, fmt.Errorf("invalid ECDSA curve")
		}
		if err != nil {
			return nil, fmt.Errorf("generate intermediate key: %w", err)
		}

	case "rsa":
		bits, err := normalizeRSABits(req.RSABits)
		if err != nil {
			return nil, err
		}

		privateKey, err = rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("generate intermediate key: %w", err)
		}

	default:
		return nil, fmt.Errorf("invalid key type")
	}

	publicKey = privateKey.Public()

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate intermediate serial: %w", err)
	}

	now := time.Now().UTC()

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = 1825
	}

	ski, err := subjectKeyID(publicKey)
	if err != nil {
		return nil, fmt.Errorf("derive intermediate subject key id: %w", err)
	}

	issuerAuthorityKeyID, err := authorityKeyID(req.IssuerCert)
	if err != nil {
		return nil, fmt.Errorf("derive issuer authority key id: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: req.CommonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski,
		AuthorityKeyId:        issuerAuthorityKeyID,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, req.IssuerCert, publicKey, req.IssuerKey)
	if err != nil {
		return nil, fmt.Errorf("create intermediate certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})

	keyPEM, err := marshalPrivateKeyPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal intermediate key: %w", err)
	}

	return &IntermediateResult{
		ID:      makeID(req.CommonName),
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

func GenerateLeafCertificate(req LeafRequest) (*LeafResult, error) {
	if req.CommonName == "" {
		return nil, fmt.Errorf("common name is required")
	}
	if req.IssuerCert == nil {
		return nil, fmt.Errorf("issuer certificate is required")
	}
	if req.IssuerKey == nil {
		return nil, fmt.Errorf("issuer key is required")
	}
	if !req.IssuerCert.IsCA {
		return nil, fmt.Errorf("issuer certificate is not a CA")
	}

	leafKey, err := generateLeafKey(req.KeyType, req.Curve, req.RSABits)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = 365
	}

	now := time.Now().UTC()

	leafSKI, err := subjectKeyID(leafKey.Public())
	if err != nil {
		return nil, fmt.Errorf("derive leaf subject key id: %w", err)
	}

	issuerAuthorityKeyID, err := authorityKeyID(req.IssuerCert)
	if err != nil {
		return nil, fmt.Errorf("derive issuer authority key id: %w", err)
	}

	keyUsage := x509.KeyUsageDigitalSignature
	if isRSAKey(leafKey) {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: req.CommonName,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              req.DNSSANs,
		IPAddresses:           req.IPSANs,
		SubjectKeyId:          leafSKI,
		AuthorityKeyId:        issuerAuthorityKeyID,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, req.IssuerCert, leafKey.Public(), req.IssuerKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})

	keyPEM, err := marshalPrivateKeyPEM(leafKey)
	if err != nil {
		return nil, fmt.Errorf("marshal leaf key: %w", err)
	}

	return &LeafResult{
		ID:      makeID(req.CommonName),
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

func generateLeafKey(keyType, curveName, rsaBits string) (crypto.Signer, error) {
	switch normalizeKeyType(keyType) {
	case "ecdsa":
		curve, err := curveFromName(curveName)
		if err != nil {
			return nil, err
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ECDSA leaf key: %w", err)
		}
		return key, nil
	case "rsa":
		bits, err := normalizeRSABits(rsaBits)
		if err != nil {
			return nil, err
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("generate RSA leaf key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

func normalizeKeyType(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	if s == "" {
		return "ecdsa"
	}
	return s
}

func curveFromName(name string) (elliptic.Curve, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "p256", "p-256", "prime256v1":
		return elliptic.P256(), nil
	case "p384", "p-384":
		return elliptic.P384(), nil
	case "p521", "p-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve")
	}
}

func normalizeRSABits(s string) (int, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " bits")
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ",", "")

	switch s {
	case "", "2048":
		return 2048, nil
	case "3072":
		return 3072, nil
	case "4096":
		return 4096, nil
	default:
		return 0, fmt.Errorf("unsupported RSA key size")
	}
}

func isRSAKey(key crypto.Signer) bool {
	_, ok := key.(*rsa.PrivateKey)
	return ok
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String() && cert.CheckSignatureFrom(cert) == nil
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	sum := sha1.Sum(spkiDER)
	return sum[:], nil
}

func authorityKeyID(cert *x509.Certificate) ([]byte, error) {
	if len(cert.SubjectKeyId) > 0 {
		return cert.SubjectKeyId, nil
	}

	return subjectKeyID(cert.PublicKey)
}

func makeID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "-")

	var b strings.Builder
	prevDash := false

	for _, r := range s {
		isAlphaNum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if isAlphaNum {
			b.WriteRune(r)
			prevDash = false
			continue
		}

		if !prevDash {
			b.WriteRune('-')
			prevDash = true
		}
	}

	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "cert"
	}
	return out
}

func normalizeCurveName(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "p384":
		return "p384"
	case "p521":
		return "p521"
	default:
		return "p256"
	}
}

func marshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}), nil

	case *rsa.PrivateKey:
		keyBytes := x509.MarshalPKCS1PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		}), nil

	default:
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
}

func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no private key PEM block found")
		}

		if key, err := parsePEMPrivateKey(block.Bytes); err == nil {
			return key, nil
		}

		if len(data) == 0 {
			return nil, fmt.Errorf("unsupported private key format")
		}
	}
}

func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no certificate PEM block found")
		}

		if block.Type != "CERTIFICATE" {
			if len(data) == 0 {
				return nil, fmt.Errorf("no certificate PEM block found")
			}
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}

		return cert, nil
	}
}

func parsePEMPrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if keyAny, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch k := keyAny.(type) {
		case *ecdsa.PrivateKey:
			return k, nil
		case *rsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported PKCS#8 private key type %T", keyAny)
		}
	}

	return nil, fmt.Errorf("unsupported private key format")
}
