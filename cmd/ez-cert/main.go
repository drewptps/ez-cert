package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"html/template"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ez-cert/internal/pki"
	"ez-cert/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type HomePageData struct {
	Nodes   []store.TreeNode
	Summary store.HomeSummary
}

type SetupPageData struct {
	Error string
}

type SetupResultPageData struct {
	RootCertPEM         string
	RootKeyPEM          string
	RootCommonName      string
	IntermediateID      string
	IntermediateSubject string
}

type RootResultPageData struct {
	RootCertPEM    string
	RootKeyPEM     string
	RootCommonName string
	RootID         string
}

type GeneratePageData struct {
	Error               string
	Success             string
	IntermediateIssuers []store.CertificateRow
	RootIssuers         []store.CertificateRow
	Form                GenerateFormValues
}

type GenerateFormValues struct {
	CertType    string
	CommonName  string
	Description string
	DNSSANs     string
	IPSANs      string
	IssuerID    string
	RootKeyPEM  string
	KeyProfile  string
	Days        string
}

type CertDetailPageData struct {
	Cert    store.CertificateDetail
	Renewed bool
}

type LoginPageData struct {
	Error string
}

type PasswordSetupPageData struct {
	Error string
}

type PasswordChangePageData struct {
	Error   string
	Success string
}

type AuditPageData struct {
	Lines []string
}

const sessionCookieName = "ezcert_session"

func sessionToken(hash []byte) string {
	mac := hmac.New(sha256.New, hash)
	mac.Write([]byte("authenticated"))
	return base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

func isValidSession(r *http.Request, hash []byte) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	expected := sessionToken(hash)
	return hmac.Equal([]byte(cookie.Value), []byte(expected))
}

func setSessionCookie(w http.ResponseWriter, hash []byte) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionToken(hash),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dir := dataDir()
		if !store.AuthHashExists(dir) {
			http.Redirect(w, r, "/password/setup", http.StatusSeeOther)
			return
		}
		hash, err := store.LoadAuthHash(dir)
		if err != nil {
			http.Error(w, "failed to load auth: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if !isValidSession(r, hash) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func requestIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func auditLog(event string) {
	if err := store.AppendAuditLog(dataDir(), event); err != nil {
		log.Printf("audit log error: %v", err)
	}
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", requireAuth(handleHome))
	mux.HandleFunc("/setup", requireAuth(handleSetup))
	mux.HandleFunc("/generate", requireAuth(handleGenerate))
	mux.HandleFunc("/cert/", requireAuth(handleCertSubroutes))
	mux.HandleFunc("/audit", requireAuth(handleAudit))
	mux.HandleFunc("/password/change", requireAuth(handlePasswordChange))
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/password/setup", handlePasswordSetup)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

	log.Println("ez-cert listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	certDir := filepath.Join(dataDir(), "certs")

	nodes, err := store.LoadTree(certDir)
	if err != nil {
		http.Error(w, "failed to load certificates: "+err.Error(), http.StatusInternalServerError)
		return
	}

	summary, err := store.LoadHomeSummary(certDir)
	if err != nil {
		http.Error(w, "failed to load summary: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles(
		"web/templates/layout.html",
		"web/templates/index.html",
	)
	if err != nil {
		http.Error(w, "failed to load template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := HomePageData{
		Nodes:   nodes,
		Summary: summary,
	}

	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "failed to render template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleCertSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/cert/")
	path = strings.Trim(path, "/")
	if path == "" {
		http.NotFound(w, r)
		return
	}

	parts := strings.Split(path, "/")

	id, ok := sanitizeID(parts[0])
	if !ok {
		http.NotFound(w, r)
		return
	}

	if len(parts) == 1 {
		handleCertDetail(w, r, id)
		return
	}

	if len(parts) == 3 && parts[1] == "export" {
		handleCertExport(w, r, id, parts[2])
		return
	}

	if len(parts) == 2 && parts[1] == "delete" {
		handleCertDelete(w, r, id)
		return
	}

	if len(parts) == 2 && parts[1] == "renew" {
		handleCertRenew(w, r, id)
		return
	}

	http.NotFound(w, r)
}

func handleCertDetail(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		http.NotFound(w, r)
		return
	}

	certDir := filepath.Join(dataDir(), "certs")

	detail, err := store.LoadCertificateDetail(certDir, id)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to load certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("web/templates/cert_detail.html")
	if err != nil {
		http.Error(w, "failed to load detail template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := CertDetailPageData{
		Cert:    detail,
		Renewed: r.URL.Query().Get("renewed") == "1",
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "failed to render detail template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleCertExport(w http.ResponseWriter, r *http.Request, id, kind string) {
	certDir := filepath.Join(dataDir(), "certs")

	var (
		filename string
		content  []byte
		err      error
	)

	switch kind {
	case "cert":
		filename = id + ".cert.pem"
		content, err = store.LoadCertificatePEM(certDir, id)
	case "key":
		filename = id + ".key.pem"
		content, err = store.LoadPrivateKeyPEM(certDir, id)
		if err == nil {
			auditLog("KEY_EXPORTED  id=" + id)
		}
	case "bundle":
		filename = id + ".bundle.pem"
		content, err = store.LoadBundlePEM(certDir, id)
	default:
		http.NotFound(w, r)
		return
	}

	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to export file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	safeFilename := strings.NewReplacer(`"`, "", "\n", "", "\r", "").Replace(filename)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFilename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func handleCertDelete(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if id == "" {
		http.NotFound(w, r)
		return
	}

	certDir := filepath.Join(dataDir(), "certs")

	canDelete, err := store.CanDeleteCertificate(certDir, id)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to inspect certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !canDelete {
		http.Error(w, "cannot delete certificate that has children", http.StatusBadRequest)
		return
	}

	if err := store.DeleteCertificate(certDir, id); err != nil {
		http.Error(w, "failed to delete certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	auditLog("CERT_DELETED  id=" + id)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderSetupForm(w, SetupPageData{})
		return
	case http.MethodPost:
		handleSetupPost(w, r)
		return
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func handleSetupPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	rootCN := strings.TrimSpace(r.FormValue("root_common_name"))
	intermediateCN := strings.TrimSpace(r.FormValue("intermediate_common_name"))

	if rootCN == "" || intermediateCN == "" {
		renderSetupForm(w, SetupPageData{
			Error: "root common name and intermediate common name are required",
		})
		return
	}

	certDir := filepath.Join(dataDir(), "certs")

	existing, err := store.LoadCertificates(certDir)
	if err != nil {
		http.Error(w, "failed to inspect existing certificates: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if len(existing) > 0 {
		http.Error(w, "setup can only be run on an empty certificate store", http.StatusBadRequest)
		return
	}

	rootResult, err := pki.GenerateRootCA(pki.RootRequest{
		CommonName:   rootCN,
		KeyType:      "ecdsa",
		Curve:        "p256",
		ValidityDays: 3650,
	})
	if err != nil {
		http.Error(w, "failed to generate root CA: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rootCert, err := pki.ParseCertificatePEM(rootResult.CertPEM)
	if err != nil {
		http.Error(w, "failed to parse generated root certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rootKey, err := pki.ParsePrivateKeyPEM(rootResult.KeyPEM)
	if err != nil {
		http.Error(w, "failed to parse generated root private key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	intermediateResult, err := pki.GenerateIntermediateCA(pki.IntermediateRequest{
		CommonName:   intermediateCN,
		IssuerCert:   rootCert,
		IssuerKey:    rootKey,
		KeyType:      "ecdsa",
		Curve:        "p256",
		ValidityDays: 1825,
	})
	if err != nil {
		http.Error(w, "failed to generate intermediate CA: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if rootResult.ID == intermediateResult.ID {
		renderSetupForm(w, SetupPageData{
			Error: "root and intermediate common names produce the same certificate ID; choose more distinct names",
		})
		return
	}

	if err := store.WriteCertificate(certDir, rootResult.ID, rootResult.CertPEM, nil); err != nil {
		http.Error(w, "failed to store root certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := store.WriteCertificate(certDir, intermediateResult.ID, intermediateResult.CertPEM, intermediateResult.KeyPEM); err != nil {
		http.Error(w, "failed to store intermediate certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	auditLog("CERT_GENERATED  id=" + rootResult.ID + "  role=root")
	auditLog("CERT_GENERATED  id=" + intermediateResult.ID + "  role=intermediate")

	tmpl, err := template.ParseFiles("web/templates/setup_result.html")
	if err != nil {
		http.Error(w, "failed to load result template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := SetupResultPageData{
		RootCertPEM:         string(rootResult.CertPEM),
		RootKeyPEM:          string(rootResult.KeyPEM),
		RootCommonName:      rootCN,
		IntermediateID:      intermediateResult.ID,
		IntermediateSubject: intermediateCN,
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "failed to render result page: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderGenerateForm(w, GeneratePageData{
			Form: GenerateFormValues{
				CertType: strings.TrimSpace(r.URL.Query().Get("cert_type")),
			},
		})
		return
	case http.MethodPost:
		handleGeneratePost(w, r)
		return
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func handleGeneratePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	form := GenerateFormValues{
		CertType:    strings.TrimSpace(r.FormValue("cert_type")),
		CommonName:  strings.TrimSpace(r.FormValue("common_name")),
		Description: strings.TrimSpace(r.FormValue("description")),
		DNSSANs:     strings.TrimSpace(r.FormValue("dns_sans")),
		IPSANs:      strings.TrimSpace(r.FormValue("ip_sans")),
		IssuerID:    strings.TrimSpace(r.FormValue("issuer_id")),
		RootKeyPEM:  strings.TrimSpace(r.FormValue("root_key_pem")),
		KeyProfile:  strings.TrimSpace(r.FormValue("key_profile")),
		Days:        strings.TrimSpace(r.FormValue("days")),
	}

	form = normalizeGenerateForm(form)

	switch form.CertType {
	case "root":
		handleGenerateRoot(w, r, form)
		return
	case "intermediate":
		handleGenerateIntermediate(w, r, form)
		return
	case "leaf":
		// continue below into leaf logic
	default:
		renderGenerateForm(w, GeneratePageData{
			Error: "invalid certificate type",
			Form:  form,
		})
		return
	}

	if form.CommonName == "" || form.IssuerID == "" {
		renderGenerateForm(w, GeneratePageData{
			Error: "common name and issuer are required",
			Form:  normalizeGenerateForm(form),
		})
		return
	}

	days, err := parseValidityDays(form.Days)
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: err.Error(),
			Form:  normalizeGenerateForm(form),
		})
		return
	}

	keyType, curve, rsaBits, err := parseKeyProfile(form.KeyProfile)
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: err.Error(),
			Form:  normalizeGenerateForm(form),
		})
		return
	}

	certDir := filepath.Join(dataDir(), "certs")

	issuer, err := store.LoadManagedCertificate(certDir, form.IssuerID)
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to load issuer: " + err.Error(),
			Form:  normalizeGenerateForm(form),
		})
		return
	}

	if issuer.Role != "intermediate" {
		renderGenerateForm(w, GeneratePageData{
			Error: "issuer must be an intermediate certificate managed by ez-cert",
			Form:  normalizeGenerateForm(form),
		})
		return
	}

	dnsSANs := parseCommaSeparatedList(form.DNSSANs)
	ipSANs, err := parseIPSANs(form.IPSANs)
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: err.Error(),
			Form:  normalizeGenerateForm(form),
		})
		return
	}

	result, err := pki.GenerateLeafCertificate(pki.LeafRequest{
		CommonName:   form.CommonName,
		DNSSANs:      dnsSANs,
		IPSANs:       ipSANs,
		IssuerCert:   issuer.Certificate,
		IssuerKey:    issuer.PrivateKey,
		KeyType:      keyType,
		Curve:        curve,
		RSABits:      rsaBits,
		ValidityDays: days,
	})
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to generate certificate: " + err.Error(),
			Form:  normalizeGenerateForm(form),
		})
		return
	}

	if err := store.WriteCertificate(certDir, result.ID, result.CertPEM, result.KeyPEM); err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to store certificate: " + err.Error(),
			Form:  normalizeGenerateForm(form),
		})
		return
	}

	if err := store.WriteDescription(certDir, result.ID, form.Description); err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to store description: " + err.Error(),
			Form:  normalizeGenerateForm(form),
		})
		return
	}

	auditLog("CERT_GENERATED  id=" + result.ID + "  role=leaf")

	renderGenerateForm(w, GeneratePageData{
		Success: "certificate generated: " + result.ID,
		Form: GenerateFormValues{
			CertType:   form.CertType,
			IssuerID:   form.IssuerID,
			KeyProfile: form.KeyProfile,
			Days:       strconv.Itoa(days),
		},
	})
}

func handleGenerateRoot(w http.ResponseWriter, r *http.Request, form GenerateFormValues) {
	if form.CommonName == "" {
		renderGenerateForm(w, GeneratePageData{
			Error: "common name is required",
			Form:  form,
		})
		return
	}

	days, err := parseValidityDays(form.Days)
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: err.Error(),
			Form:  form,
		})
		return
	}

	keyType, curve, rsaBits, err := parseKeyProfile(form.KeyProfile)
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: err.Error(),
			Form:  form,
		})
		return
	}

	result, err := pki.GenerateRootCA(pki.RootRequest{
		CommonName:   form.CommonName,
		KeyType:      keyType,
		Curve:        curve,
		RSABits:      rsaBits,
		ValidityDays: days,
	})
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to generate root CA: " + err.Error(),
			Form:  form,
		})
		return
	}

	certDir := filepath.Join(dataDir(), "certs")

	if err := store.WriteCertificate(certDir, result.ID, result.CertPEM, nil); err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to store root certificate: " + err.Error(),
			Form:  form,
		})
		return
	}

	if err := store.WriteDescription(certDir, result.ID, form.Description); err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to store description: " + err.Error(),
			Form:  form,
		})
		return
	}

	auditLog("CERT_GENERATED  id=" + result.ID + "  role=root")

	tmpl, err := template.ParseFiles("web/templates/root_result.html")
	if err != nil {
		http.Error(w, "failed to load root result template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := RootResultPageData{
		RootCertPEM:    string(result.CertPEM),
		RootKeyPEM:     string(result.KeyPEM),
		RootCommonName: form.CommonName,
		RootID:         result.ID,
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "failed to render root result page: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleGenerateIntermediate(w http.ResponseWriter, r *http.Request, form GenerateFormValues) {
	if form.CommonName == "" {
		renderGenerateForm(w, GeneratePageData{
			Error: "common name is required",
			Form:  form,
		})
		return
	}

	if form.IssuerID == "" {
		renderGenerateForm(w, GeneratePageData{
			Error: "issuer root is required",
			Form:  form,
		})
		return
	}

	if form.RootKeyPEM == "" {
		renderGenerateForm(w, GeneratePageData{
			Error: "root private key PEM is required",
			Form:  form,
		})
		return
	}

	days, err := parseValidityDays(form.Days)
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: err.Error(),
			Form:  form,
		})
		return
	}

	keyType, curve, rsaBits, err := parseKeyProfile(form.KeyProfile)
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: err.Error(),
			Form:  form,
		})
		return
	}

	certDir := filepath.Join(dataDir(), "certs")

	issuer, err := store.LoadStoredCertificate(certDir, form.IssuerID)
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to load issuer root: " + err.Error(),
			Form:  form,
		})
		return
	}

	if issuer.Role != "root" {
		renderGenerateForm(w, GeneratePageData{
			Error: "issuer must be a root CA managed by ez-cert",
			Form:  form,
		})
		return
	}

	issuerKey, err := pki.ParsePrivateKeyPEM([]byte(form.RootKeyPEM))
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to parse root private key: " + err.Error(),
			Form:  form,
		})
		return
	}

	matches, err := signerMatchesCertificate(issuer.Certificate, issuerKey)
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to validate root private key: " + err.Error(),
			Form:  form,
		})
		return
	}

	if !matches {
		renderGenerateForm(w, GeneratePageData{
			Error: "provided root private key does not match the selected root certificate",
			Form:  form,
		})
		return
	}

	result, err := pki.GenerateIntermediateCA(pki.IntermediateRequest{
		CommonName:   form.CommonName,
		IssuerCert:   issuer.Certificate,
		IssuerKey:    issuerKey,
		KeyType:      keyType,
		Curve:        curve,
		RSABits:      rsaBits,
		ValidityDays: days,
	})
	if err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to generate intermediate CA: " + err.Error(),
			Form:  form,
		})
		return
	}

	if err := store.WriteCertificate(certDir, result.ID, result.CertPEM, result.KeyPEM); err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to store intermediate CA: " + err.Error(),
			Form:  form,
		})
		return
	}

	if err := store.WriteDescription(certDir, result.ID, form.Description); err != nil {
		renderGenerateForm(w, GeneratePageData{
			Error: "failed to store description: " + err.Error(),
			Form:  form,
		})
		return
	}

	auditLog("CERT_GENERATED  id=" + result.ID + "  role=intermediate")

	renderGenerateForm(w, GeneratePageData{
		Success: "intermediate CA generated: " + result.ID,
		Form: GenerateFormValues{
			CertType:   "intermediate",
			IssuerID:   form.IssuerID,
			KeyProfile: form.KeyProfile,
			Days:       strconv.Itoa(days),
		},
	})
}

func renderGenerateForm(w http.ResponseWriter, data GeneratePageData) {
	certDir := filepath.Join(dataDir(), "certs")

	data.Form = normalizeGenerateForm(data.Form)

	rows, err := store.LoadCertificates(certDir)
	if err != nil {
		http.Error(w, "failed to load issuers: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var rootIssuers []store.CertificateRow
	var intermediateIssuers []store.CertificateRow

	for _, row := range rows {
		switch row.Role {
		case "root":
			rootIssuers = append(rootIssuers, row)
		case "intermediate":
			intermediateIssuers = append(intermediateIssuers, row)
		}
	}

	if data.Form.CertType == "leaf" && data.Form.IssuerID == "" && len(intermediateIssuers) > 0 {
		data.Form.IssuerID = intermediateIssuers[0].ID
	}

	if data.Form.CertType == "intermediate" && data.Form.IssuerID == "" && len(rootIssuers) > 0 {
		data.Form.IssuerID = rootIssuers[0].ID
	}

	data.RootIssuers = rootIssuers
	data.IntermediateIssuers = intermediateIssuers

	tmpl, err := template.ParseFiles("web/templates/generate.html")
	if err != nil {
		http.Error(w, "failed to load generate template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "failed to render generate template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func renderSetupForm(w http.ResponseWriter, data SetupPageData) {
	tmpl, err := template.ParseFiles("web/templates/setup.html")
	if err != nil {
		http.Error(w, "failed to load setup template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "failed to render setup template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func dataDir() string {
	if v := os.Getenv("EZCERT_DATA_DIR"); v != "" {
		return v
	}
	return "./data"
}

func parseCommaSeparatedList(s string) []string {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))

	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		out = append(out, v)
	}

	return out
}

func parseIPSANs(s string) ([]net.IP, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}

	parts := strings.Split(s, ",")
	out := make([]net.IP, 0, len(parts))

	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}

		ip := net.ParseIP(v)
		if ip == nil {
			return nil, httpError("invalid IP SAN: " + v)
		}

		out = append(out, ip)
	}

	return out, nil
}

func normalizeCertType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "root":
		return "root"
	case "intermediate":
		return "intermediate"
	default:
		return "leaf"
	}
}

func normalizeGenerateForm(form GenerateFormValues) GenerateFormValues {
	form.CertType = normalizeCertType(form.CertType)

	if form.KeyProfile == "" {
		form.KeyProfile = "ecdsa-p256"
	}

	if form.Days == "" {
		switch form.CertType {
		case "root":
			form.Days = "3650"
		case "intermediate":
			form.Days = "1825"
		default:
			form.Days = "365"
		}
	}

	return form
}

func parseValidityDays(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 365, nil
	}

	days, err := strconv.Atoi(s)
	if err != nil {
		return 0, httpError("validity must be a whole number of days")
	}
	if days < 1 {
		return 0, httpError("validity must be at least 1 day")
	}
	if days > 3650 {
		return 0, httpError("validity must be 3650 days or less")
	}
	return days, nil
}

type httpError string

func (e httpError) Error() string { return string(e) }

func parseKeyProfile(profile string) (keyType, curve, rsaBits string, err error) {
	switch strings.TrimSpace(profile) {
	case "", "ecdsa-p256":
		return "ecdsa", "p256", "", nil
	case "ecdsa-p384":
		return "ecdsa", "p384", "", nil
	case "ecdsa-p521":
		return "ecdsa", "p521", "", nil
	case "rsa-2048":
		return "rsa", "", "2048", nil
	case "rsa-3072":
		return "rsa", "", "3072", nil
	case "rsa-4096":
		return "rsa", "", "4096", nil
	default:
		return "", "", "", httpError("invalid key profile")
	}
}

func signerMatchesCertificate(cert *x509.Certificate, signer crypto.Signer) (bool, error) {
	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false, err
	}

	signerPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return false, err
	}

	return bytes.Equal(certPub, signerPub), nil
}

func handleCertRenew(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	certDir := filepath.Join(dataDir(), "certs")

	stored, err := store.LoadStoredCertificate(certDir, id)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to load certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	switch stored.Role {
	case "leaf":
		handleLeafRenew(w, r, id, stored, certDir)
	case "intermediate":
		handleIntermediateRenew(w, r, id, stored, certDir)
	default:
		http.Error(w, "root certificate renewal is not supported", http.StatusBadRequest)
	}
}

func handleLeafRenew(w http.ResponseWriter, r *http.Request, id string, stored *store.StoredCertificate, certDir string) {
	cert := stored.Certificate

	issuerID, err := store.FindIssuerID(certDir, cert)
	if err != nil {
		http.Error(w, "failed to find issuer: "+err.Error(), http.StatusInternalServerError)
		return
	}

	issuer, err := store.LoadManagedCertificate(certDir, issuerID)
	if err != nil {
		http.Error(w, "failed to load issuer: "+err.Error(), http.StatusInternalServerError)
		return
	}

	keyType, curve, rsaBits := deriveKeyParams(cert)
	validityDays := certValidityDays(cert)

	result, err := pki.GenerateLeafCertificate(pki.LeafRequest{
		CommonName:   cert.Subject.CommonName,
		DNSSANs:      cert.DNSNames,
		IPSANs:       cert.IPAddresses,
		IssuerCert:   issuer.Certificate,
		IssuerKey:    issuer.PrivateKey,
		KeyType:      keyType,
		Curve:        curve,
		RSABits:      rsaBits,
		ValidityDays: validityDays,
	})
	if err != nil {
		http.Error(w, "failed to renew certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := store.RenewCertificate(certDir, id, result.CertPEM, result.KeyPEM); err != nil {
		http.Error(w, "failed to save renewed certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	auditLog("CERT_RENEWED  id=" + id + "  role=leaf")
	http.Redirect(w, r, "/cert/"+id+"?renewed=1", http.StatusSeeOther)
}

func handleIntermediateRenew(w http.ResponseWriter, r *http.Request, id string, stored *store.StoredCertificate, certDir string) {
	cert := stored.Certificate

	rootKeyPEM := strings.TrimSpace(r.FormValue("root_key_pem"))
	if rootKeyPEM == "" {
		http.Error(w, "root private key PEM is required", http.StatusBadRequest)
		return
	}

	issuerID, err := store.FindIssuerID(certDir, cert)
	if err != nil {
		http.Error(w, "failed to find issuer: "+err.Error(), http.StatusInternalServerError)
		return
	}

	issuer, err := store.LoadStoredCertificate(certDir, issuerID)
	if err != nil {
		http.Error(w, "failed to load issuer: "+err.Error(), http.StatusInternalServerError)
		return
	}

	issuerKey, err := pki.ParsePrivateKeyPEM([]byte(rootKeyPEM))
	if err != nil {
		http.Error(w, "failed to parse root private key: "+err.Error(), http.StatusBadRequest)
		return
	}

	matches, err := signerMatchesCertificate(issuer.Certificate, issuerKey)
	if err != nil {
		http.Error(w, "failed to validate root private key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !matches {
		http.Error(w, "provided root private key does not match the issuer certificate", http.StatusBadRequest)
		return
	}

	keyType, curve, rsaBits := deriveKeyParams(cert)
	validityDays := certValidityDays(cert)

	result, err := pki.GenerateIntermediateCA(pki.IntermediateRequest{
		CommonName:   cert.Subject.CommonName,
		IssuerCert:   issuer.Certificate,
		IssuerKey:    issuerKey,
		KeyType:      keyType,
		Curve:        curve,
		RSABits:      rsaBits,
		ValidityDays: validityDays,
	})
	if err != nil {
		http.Error(w, "failed to renew intermediate CA: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := store.RenewCertificate(certDir, id, result.CertPEM, result.KeyPEM); err != nil {
		http.Error(w, "failed to save renewed certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	auditLog("CERT_RENEWED  id=" + id + "  role=intermediate")
	http.Redirect(w, r, "/cert/"+id+"?renewed=1", http.StatusSeeOther)
}

func deriveKeyParams(cert *x509.Certificate) (keyType, curve, rsaBits string) {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		keyType = "ecdsa"
		switch pub.Curve.Params().Name {
		case "P-384":
			curve = "p384"
		case "P-521":
			curve = "p521"
		default:
			curve = "p256"
		}
	case *rsa.PublicKey:
		keyType = "rsa"
		rsaBits = strconv.Itoa(pub.N.BitLen())
	default:
		keyType = "ecdsa"
		curve = "p256"
	}
	return
}

func certValidityDays(cert *x509.Certificate) int {
	days := int(math.Round(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24))
	if days < 1 {
		return 1
	}
	return days
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	dir := dataDir()

	// If no password has been set yet, redirect to setup.
	if !store.AuthHashExists(dir) {
		http.Redirect(w, r, "/password/setup", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		renderTemplate(w, "web/templates/login.html", LoginPageData{})
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	password := r.FormValue("password")

	hash, err := store.LoadAuthHash(dir)
	if err != nil {
		http.Error(w, "failed to load auth: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		auditLog("LOGIN_FAILED  ip=" + requestIP(r))
		renderTemplate(w, "web/templates/login.html", LoginPageData{Error: "Incorrect password."})
		return
	}

	auditLog("LOGIN_SUCCESS  ip=" + requestIP(r))
	setSessionCookie(w, hash)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	auditLog("LOGOUT  ip=" + requestIP(r))
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handlePasswordSetup(w http.ResponseWriter, r *http.Request) {
	dir := dataDir()

	// Setup is only allowed when no password exists yet.
	if store.AuthHashExists(dir) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		renderTemplate(w, "web/templates/password_setup.html", PasswordSetupPageData{})
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if password == "" {
		renderTemplate(w, "web/templates/password_setup.html", PasswordSetupPageData{Error: "Password cannot be empty."})
		return
	}
	if password != confirm {
		renderTemplate(w, "web/templates/password_setup.html", PasswordSetupPageData{Error: "Passwords do not match."})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "failed to hash password: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := store.WriteAuthHash(dir, hash); err != nil {
		http.Error(w, "failed to save password: "+err.Error(), http.StatusInternalServerError)
		return
	}

	auditLog("PASSWORD_SET  ip=" + requestIP(r))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTemplate(w, "web/templates/password_change.html", PasswordChangePageData{})
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	current := r.FormValue("current")
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	dir := dataDir()
	hash, err := store.LoadAuthHash(dir)
	if err != nil {
		http.Error(w, "failed to load auth: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword(hash, []byte(current)); err != nil {
		renderTemplate(w, "web/templates/password_change.html", PasswordChangePageData{Error: "Current password is incorrect."})
		return
	}

	if password == "" {
		renderTemplate(w, "web/templates/password_change.html", PasswordChangePageData{Error: "New password cannot be empty."})
		return
	}
	if password != confirm {
		renderTemplate(w, "web/templates/password_change.html", PasswordChangePageData{Error: "New passwords do not match."})
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "failed to hash password: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := store.WriteAuthHash(dir, newHash); err != nil {
		http.Error(w, "failed to save password: "+err.Error(), http.StatusInternalServerError)
		return
	}

	auditLog("PASSWORD_CHANGED  ip=" + requestIP(r))
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	lines, err := store.LoadAuditLogLines(dataDir())
	if err != nil {
		http.Error(w, "failed to load audit log: "+err.Error(), http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "web/templates/audit.html", AuditPageData{Lines: lines})
}

func renderTemplate(w http.ResponseWriter, path string, data any) {
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		http.Error(w, "failed to load template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}

func sanitizeID(id string) (string, bool) {
	if id == "" {
		return "", false
	}
	if strings.Contains(id, "/") || strings.Contains(id, "\\") || strings.Contains(id, "..") || strings.Contains(id, "\x00") {
		return "", false
	}
	return id, true
}
