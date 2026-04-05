package store

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type CertificateRow struct {
	ID         string
	CommonName string
	Role       string
	NotAfter   time.Time
	Status     string
	IssuerName string
}

type ManagedCertificate struct {
	ID          string
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	Role        string
}

type StoredCertificate struct {
	ID          string
	Certificate *x509.Certificate
	Role        string
}

type TreeNode struct {
	ID           string
	CommonName   string
	Role         string
	Status       string
	NotAfter     time.Time
	Depth        int
	ExpiresIn    string
	ValidityText string
}

type CertificateChainLink struct {
	ID         string
	CommonName string
	Role       string
}

type CertificateDetail struct {
	ID               string
	CommonName       string
	Role             string
	Status           string
	ValidityText     string
	IssuerCommonName string
	NotBefore        time.Time
	NotAfter         time.Time
	ExpiresIn        string
	DNSSANs          []string
	IPSANs           []string
	KeyType          string
	HasPrivateKey    bool
	HasChildren      bool
	SubjectKeyID     string
	AuthorityKeyID   string
	Chain            []CertificateChainLink
	Description      string
}

type HomeSummary struct {
	Total         int
	Roots         int
	Intermediates int
	Leaves        int
	ExpiringSoon  int
}

func LoadCertificates(baseDir string) ([]CertificateRow, error) {
	certs, err := loadAllCertificates(baseDir)
	if err != nil {
		return nil, err
	}

	rows := make([]CertificateRow, 0, len(certs))
	now := time.Now()

	for _, item := range certs {
		rows = append(rows, CertificateRow{
			ID:         item.ID,
			CommonName: item.Certificate.Subject.CommonName,
			Role:       deriveRole(item.Certificate),
			NotAfter:   item.Certificate.NotAfter,
			Status:     deriveStatus(item.Certificate, now),
			IssuerName: item.Certificate.Issuer.CommonName,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		return strings.ToLower(rows[i].ID) < strings.ToLower(rows[j].ID)
	})

	return rows, nil
}

func LoadManagedCertificate(baseDir, id string) (*ManagedCertificate, error) {
	certPath := filepath.Join(baseDir, id, "cert.pem")
	keyPath := filepath.Join(baseDir, id, "key.pem")

	cert, err := readCertificateFromPEMFile(certPath)
	if err != nil {
		return nil, err
	}

	key, err := readPrivateKeyFromPEMFile(keyPath)
	if err != nil {
		return nil, err
	}

	return &ManagedCertificate{
		ID:          id,
		Certificate: cert,
		PrivateKey:  key,
		Role:        deriveRole(cert),
	}, nil
}

func LoadStoredCertificate(baseDir, id string) (*StoredCertificate, error) {
	certPath := filepath.Join(baseDir, id, "cert.pem")

	cert, err := readCertificateFromPEMFile(certPath)
	if err != nil {
		return nil, err
	}

	return &StoredCertificate{
		ID:          id,
		Certificate: cert,
		Role:        deriveRole(cert),
	}, nil
}

func LoadCertificateDetail(baseDir, id string) (CertificateDetail, error) {
	certPath := filepath.Join(baseDir, id, "cert.pem")

	cert, err := readCertificateFromPEMFile(certPath)
	if err != nil {
		return CertificateDetail{}, err
	}

	keyPath := filepath.Join(baseDir, id, "key.pem")
	_, keyErr := readPrivateKeyFromPEMFile(keyPath)

	allCerts, err := loadAllCertificates(baseDir)
	if err != nil {
		return CertificateDetail{}, err
	}

	now := time.Now()
	status := deriveStatus(cert, now)

	description, err := LoadDescription(baseDir, id)
	if err != nil {
		return CertificateDetail{}, err
	}

	return CertificateDetail{
		ID:               id,
		CommonName:       cert.Subject.CommonName,
		Role:             deriveRole(cert),
		Status:           status,
		ValidityText:     formatValidity(status),
		IssuerCommonName: cert.Issuer.CommonName,
		NotBefore:        cert.NotBefore,
		NotAfter:         cert.NotAfter,
		ExpiresIn:        formatExpiresIn(cert.NotAfter, now),
		DNSSANs:          cert.DNSNames,
		IPSANs:           ipStrings(cert.IPAddresses),
		KeyType:          publicKeyType(cert.PublicKey),
		HasPrivateKey:    keyErr == nil,
		HasChildren:      certificateHasChildren(id, cert, allCerts),
		SubjectKeyID:     formatHex(cert.SubjectKeyId),
		AuthorityKeyID:   formatHex(cert.AuthorityKeyId),
		Chain:            buildChainLinks(id, cert, allCerts),
		Description:      description,
	}, nil
}

func LoadHomeSummary(baseDir string) (HomeSummary, error) {
	certs, err := loadAllCertificates(baseDir)
	if err != nil {
		return HomeSummary{}, err
	}

	now := time.Now()
	var summary HomeSummary

	for _, item := range certs {
		summary.Total++

		switch deriveRole(item.Certificate) {
		case "root":
			summary.Roots++
		case "intermediate":
			summary.Intermediates++
		default:
			summary.Leaves++
		}

		if deriveStatus(item.Certificate, now) == "warning" {
			summary.ExpiringSoon++
		}
	}

	return summary, nil
}

func LoadTree(baseDir string) ([]TreeNode, error) {
	certs, err := loadAllCertificates(baseDir)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return []TreeNode{}, nil
	}

	now := time.Now()

	type certItem struct {
		ID   string
		Cert *x509.Certificate
	}

	bySubjectKeyID := make(map[string]certItem)
	childrenByParentID := make(map[string][]certItem)
	var roots []certItem
	var orphans []certItem

	for _, item := range certs {
		current := certItem{
			ID:   item.ID,
			Cert: item.Certificate,
		}

		if isSelfSigned(item.Certificate) {
			roots = append(roots, current)
		}

		ski := string(item.Certificate.SubjectKeyId)
		if ski != "" {
			bySubjectKeyID[ski] = current
		}
	}

	hasParent := make(map[string]bool)

	for _, item := range certs {
		if isSelfSigned(item.Certificate) {
			continue
		}

		parent, ok := bySubjectKeyID[string(item.Certificate.AuthorityKeyId)]
		if !ok {
			orphans = append(orphans, certItem{
				ID:   item.ID,
				Cert: item.Certificate,
			})
			continue
		}

		childrenByParentID[parent.ID] = append(childrenByParentID[parent.ID], certItem{
			ID:   item.ID,
			Cert: item.Certificate,
		})
		hasParent[item.ID] = true
	}

	for _, item := range certs {
		if isSelfSigned(item.Certificate) {
			continue
		}
		if hasParent[item.ID] {
			continue
		}

		found := false
		for _, orphan := range orphans {
			if orphan.ID == item.ID {
				found = true
				break
			}
		}
		if !found {
			orphans = append(orphans, certItem{
				ID:   item.ID,
				Cert: item.Certificate,
			})
		}
	}

	sort.Slice(roots, func(i, j int) bool {
		return compareCertItems(roots[i], roots[j])
	})

	sort.Slice(orphans, func(i, j int) bool {
		return compareCertItems(orphans[i], orphans[j])
	})

	for parentID := range childrenByParentID {
		sort.Slice(childrenByParentID[parentID], func(i, j int) bool {
			return compareCertItems(childrenByParentID[parentID][i], childrenByParentID[parentID][j])
		})
	}

	var nodes []TreeNode

	var walk func(item certItem, depth int)
	walk = func(item certItem, depth int) {
		status := deriveStatus(item.Cert, now)

		nodes = append(nodes, TreeNode{
			ID:           item.ID,
			CommonName:   item.Cert.Subject.CommonName,
			Role:         deriveRole(item.Cert),
			Status:       status,
			NotAfter:     item.Cert.NotAfter,
			Depth:        depth,
			ExpiresIn:    formatExpiresIn(item.Cert.NotAfter, now),
			ValidityText: formatValidity(status),
		})

		for _, child := range childrenByParentID[item.ID] {
			walk(child, depth+1)
		}
	}

	for _, root := range roots {
		walk(root, 0)
	}

	for _, orphan := range orphans {
		walk(orphan, 0)
	}

	return nodes, nil
}

func LoadCertificatePEM(baseDir, id string) ([]byte, error) {
	return os.ReadFile(filepath.Join(baseDir, id, "cert.pem"))
}

func LoadPrivateKeyPEM(baseDir, id string) ([]byte, error) {
	return os.ReadFile(filepath.Join(baseDir, id, "key.pem"))
}

func LoadBundlePEM(baseDir, id string) ([]byte, error) {
	currentCert, err := readCertificateFromPEMFile(filepath.Join(baseDir, id, "cert.pem"))
	if err != nil {
		return nil, err
	}

	allCerts, err := loadAllCertificates(baseDir)
	if err != nil {
		return nil, err
	}

	links := buildChainLinks(id, currentCert, allCerts)
	if len(links) == 0 {
		return LoadCertificatePEM(baseDir, id)
	}

	var bundle bytes.Buffer

	for i := len(links) - 1; i >= 0; i-- {
		pemBytes, err := LoadCertificatePEM(baseDir, links[i].ID)
		if err != nil {
			return nil, err
		}
		bundle.Write(bytes.TrimSpace(pemBytes))
		bundle.WriteString("\n")
	}

	return bundle.Bytes(), nil
}

func CertificateIDExists(baseDir, id string) (bool, error) {
	_, err := os.Stat(filepath.Join(baseDir, id))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func WriteCertificate(baseDir, id string, certPEM, keyPEM []byte) error {
	dir := filepath.Join(baseDir, id)

	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("certificate ID already exists: %s", id)
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}

	if len(keyPEM) > 0 {
		keyPath := filepath.Join(dir, "key.pem")
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return err
		}
	}

	return nil
}

// WriteDescription saves an optional human-readable description for a
// certificate. The description is stored as a plain text file alongside
// cert.pem and key.pem. Passing an empty string is a no-op so that callers
// do not need to special-case optional descriptions.
func WriteDescription(baseDir, id, description string) error {
	description = strings.TrimSpace(description)
	if description == "" {
		return nil
	}

	path := filepath.Join(baseDir, id, "description.txt")
	return os.WriteFile(path, []byte(description), 0o644)
}

// LoadDescription reads the description for a certificate. If no description
// file exists an empty string is returned without an error, since descriptions
// are optional.
func LoadDescription(baseDir, id string) (string, error) {
	path := filepath.Join(baseDir, id, "description.txt")

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

func loadAllCertificates(baseDir string) ([]ManagedCertificate, error) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []ManagedCertificate{}, nil
		}
		return nil, err
	}

	var out []ManagedCertificate

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		id := entry.Name()
		certPath := filepath.Join(baseDir, id, "cert.pem")

		cert, err := readCertificateFromPEMFile(certPath)
		if err != nil {
			log.Printf("skipping %s: %v", id, err)
			continue
		}

		out = append(out, ManagedCertificate{
			ID:          id,
			Certificate: cert,
			Role:        deriveRole(cert),
		})
	}

	return out, nil
}

func buildChainLinks(id string, cert *x509.Certificate, allCerts []ManagedCertificate) []CertificateChainLink {
	type certItem struct {
		ID   string
		Cert *x509.Certificate
	}

	bySubjectKeyID := make(map[string]certItem)
	for _, item := range allCerts {
		if len(item.Certificate.SubjectKeyId) == 0 {
			continue
		}
		bySubjectKeyID[string(item.Certificate.SubjectKeyId)] = certItem{
			ID:   item.ID,
			Cert: item.Certificate,
		}
	}

	currentID := id
	currentCert := cert
	var reverse []CertificateChainLink

	for {
		reverse = append(reverse, CertificateChainLink{
			ID:         currentID,
			CommonName: currentCert.Subject.CommonName,
			Role:       deriveRole(currentCert),
		})

		if isSelfSigned(currentCert) {
			break
		}

		parent, ok := bySubjectKeyID[string(currentCert.AuthorityKeyId)]
		if !ok {
			break
		}

		if parent.ID == currentID {
			break
		}

		currentID = parent.ID
		currentCert = parent.Cert
	}

	chain := make([]CertificateChainLink, 0, len(reverse))
	for i := len(reverse) - 1; i >= 0; i-- {
		chain = append(chain, reverse[i])
	}

	return chain
}

func readCertificateFromPEMFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no certificate PEM block found in %s", path)
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate %s: %w", path, err)
			}
			return cert, nil
		}
	}
}

func readPrivateKeyFromPEMFile(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		key, err := parsePEMPrivateKey(block.Bytes)
		if err == nil {
			return key, nil
		}
	}

	return nil, fmt.Errorf("no private key PEM block found in %s", path)
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
		case ed25519.PrivateKey:
			return k, nil
		case *ecdh.PrivateKey:
			return nil, fmt.Errorf("ecdh keys are not valid signing keys")
		default:
			return nil, fmt.Errorf("unsupported PKCS#8 private key type %T", keyAny)
		}
	}

	return nil, fmt.Errorf("unsupported private key format")
}

func deriveRole(cert *x509.Certificate) string {
	if cert.IsCA {
		if isSelfSigned(cert) {
			return "root"
		}
		return "intermediate"
	}

	return "leaf"
}

func deriveStatus(cert *x509.Certificate, now time.Time) string {
	if now.After(cert.NotAfter) {
		return "expired"
	}

	if cert.NotAfter.Sub(now) <= 30*24*time.Hour {
		return "warning"
	}

	return "valid"
}

func formatExpiresIn(notAfter, now time.Time) string {
	if now.After(notAfter) {
		days := int(math.Ceil(now.Sub(notAfter).Hours() / 24))
		if days <= 0 {
			days = 1
		}
		if days == 1 {
			return "expired 1 day ago"
		}
		return fmt.Sprintf("expired %d days ago", days)
	}

	days := int(math.Ceil(notAfter.Sub(now).Hours() / 24))
	if days <= 0 {
		days = 0
	}

	if days == 0 {
		return "today"
	}
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}

func formatValidity(status string) string {
	switch status {
	case "expired":
		return "Expired"
	case "warning":
		return "Expiring Soon"
	default:
		return "Valid"
	}
}

func ipStrings(ips []net.IP) []string {
	if len(ips) == 0 {
		return nil
	}

	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func formatHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func publicKeyType(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		curveName := ""
		if k.Curve != nil {
			curveName = k.Curve.Params().Name
		}
		if curveName != "" {
			return "ECDSA (" + curveName + ")"
		}
		return "ECDSA"
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA (%d bits)", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", pub)
	}
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String() && cert.CheckSignatureFrom(cert) == nil
}

func compareCertItems(a, b struct {
	ID   string
	Cert *x509.Certificate
}) bool {
	roleRank := func(cert *x509.Certificate) int {
		switch deriveRole(cert) {
		case "root":
			return 0
		case "intermediate":
			return 1
		default:
			return 2
		}
	}

	ar := roleRank(a.Cert)
	br := roleRank(b.Cert)
	if ar != br {
		return ar < br
	}

	return strings.ToLower(a.ID) < strings.ToLower(b.ID)
}

func certificateHasChildren(id string, cert *x509.Certificate, allCerts []ManagedCertificate) bool {
	if len(cert.SubjectKeyId) == 0 {
		return false
	}

	for _, item := range allCerts {
		if item.ID == id {
			continue
		}
		if len(item.Certificate.AuthorityKeyId) == 0 {
			continue
		}
		if string(item.Certificate.AuthorityKeyId) == string(cert.SubjectKeyId) {
			return true
		}
	}

	return false
}

func RenewCertificate(baseDir, id string, certPEM, keyPEM []byte) error {
	dir := filepath.Join(baseDir, id)

	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("certificate %s does not exist", id)
		}
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
		return err
	}

	if len(keyPEM) > 0 {
		if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
			return err
		}
	}

	return nil
}

func FindIssuerID(baseDir string, cert *x509.Certificate) (string, error) {
	if len(cert.AuthorityKeyId) == 0 {
		return "", fmt.Errorf("certificate has no authority key identifier")
	}

	allCerts, err := loadAllCertificates(baseDir)
	if err != nil {
		return "", err
	}

	for _, item := range allCerts {
		if string(item.Certificate.SubjectKeyId) == string(cert.AuthorityKeyId) {
			return item.ID, nil
		}
	}

	return "", fmt.Errorf("issuer certificate not found in store")
}

func DeleteCertificate(baseDir, id string) error {
	return os.RemoveAll(filepath.Join(baseDir, id))
}

func CanDeleteCertificate(baseDir, id string) (bool, error) {
	certPath := filepath.Join(baseDir, id, "cert.pem")

	cert, err := readCertificateFromPEMFile(certPath)
	if err != nil {
		return false, err
	}

	allCerts, err := loadAllCertificates(baseDir)
	if err != nil {
		return false, err
	}

	return !certificateHasChildren(id, cert, allCerts), nil
}
