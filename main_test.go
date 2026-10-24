package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	zone      = "asobi.dev"
	namespace = "cert-manager"
	token     = "secret-token"
)

type fakeDesec struct {
	mu     sync.Mutex
	rrsets map[string][]string
	calls  []string
}

func (f *fakeDesec) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)

	if r.Header.Get("Authorization") != "Token "+token {
		http.Error(w, `{"detail":"bad token"}`, http.StatusUnauthorized)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	if path == "domains/" {
		var domains []map[string]string
		if q := r.URL.Query().Get("owns_qname"); q == zone || strings.HasSuffix(q, "."+zone) {
			domains = append(domains, map[string]string{"name": zone})
		}
		writeJSON(w, http.StatusOK, domains)
		return
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 3 && r.Method == http.MethodPost {
		var body struct {
			SubName string   `json:"subname"`
			Records []string `json:"records"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, ok := f.rrsets[body.SubName]; ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "exists"})
			return
		}
		f.rrsets[body.SubName] = body.Records
		writeJSON(w, http.StatusCreated, rrset(body.SubName, body.Records))
		return
	}
	if len(parts) != 5 || parts[0] != "domains" || parts[1] != zone || parts[4] != "TXT" {
		http.Error(w, `{"detail":"unexpected"}`, http.StatusTeapot)
		return
	}

	sub := parts[3]
	records, ok := f.rrsets[sub]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Not found."})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, rrset(sub, records))
	case http.MethodPatch:
		var body struct {
			Records []string `json:"records"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.rrsets[sub] = body.Records
		writeJSON(w, http.StatusOK, rrset(sub, body.Records))
	case http.MethodDelete:
		delete(f.rrsets, sub)
		w.WriteHeader(http.StatusNoContent)
	}
}

func rrset(sub string, records []string) map[string]any {
	return map[string]any{"domain": zone, "subname": sub, "type": "TXT", "ttl": recordTTL, "records": records}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func setup(t *testing.T, rrsets map[string][]string) (*desecDNSProviderSolver, *fakeDesec) {
	t.Helper()
	api := &fakeDesec{rrsets: rrsets}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	client := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "desec-token", Namespace: namespace},
		Data:       map[string][]byte{"token": []byte(token + "\n")},
	})
	return &desecDNSProviderSolver{client: client, baseURL: srv.URL + "/api/v1/"}, api
}

func challenge(fqdn, key string) *v1alpha1.ChallengeRequest {
	return &v1alpha1.ChallengeRequest{
		ResolvedFQDN:      fqdn,
		Key:               key,
		ResourceNamespace: namespace,
		Config:            &extapi.JSON{Raw: []byte(`{"apiKeySecretRef":{"name":"desec-token","key":"token"}}`)},
	}
}

func TestPresentCreatesRRset(t *testing.T) {
	solver, api := setup(t, map[string][]string{})
	if err := solver.Present(challenge("_acme-challenge.game.asobi.dev.", "k1")); err != nil {
		t.Fatal(err)
	}
	if got := api.rrsets["_acme-challenge.game"]; !slices.Equal(got, []string{`"k1"`}) {
		t.Fatalf("records = %v", got)
	}
}

func TestPresentKeepsExistingKeys(t *testing.T) {
	solver, api := setup(t, map[string][]string{"_acme-challenge": {`"other"`}})
	if err := solver.Present(challenge("_acme-challenge.asobi.dev.", "k1")); err != nil {
		t.Fatal(err)
	}
	if got := api.rrsets["_acme-challenge"]; !slices.Equal(got, []string{`"other"`, `"k1"`}) {
		t.Fatalf("records = %v", got)
	}
}

func TestPresentIsIdempotent(t *testing.T) {
	solver, api := setup(t, map[string][]string{"_acme-challenge": {`"k1"`}})
	if err := solver.Present(challenge("_acme-challenge.asobi.dev.", "k1")); err != nil {
		t.Fatal(err)
	}
	if got := api.rrsets["_acme-challenge"]; !slices.Equal(got, []string{`"k1"`}) {
		t.Fatalf("records = %v", got)
	}
	for _, call := range api.calls {
		if !strings.HasPrefix(call, http.MethodGet) {
			t.Fatalf("unexpected write %s", call)
		}
	}
}

func TestCleanUpRemovesOnlyOwnKey(t *testing.T) {
	solver, api := setup(t, map[string][]string{"_acme-challenge": {`"other"`, `"k1"`}})
	if err := solver.CleanUp(challenge("_acme-challenge.asobi.dev.", "k1")); err != nil {
		t.Fatal(err)
	}
	if got := api.rrsets["_acme-challenge"]; !slices.Equal(got, []string{`"other"`}) {
		t.Fatalf("records = %v", got)
	}
}

func TestCleanUpDeletesEmptyRRset(t *testing.T) {
	solver, api := setup(t, map[string][]string{"_acme-challenge": {`"k1"`}})
	if err := solver.CleanUp(challenge("_acme-challenge.asobi.dev.", "k1")); err != nil {
		t.Fatal(err)
	}
	if _, ok := api.rrsets["_acme-challenge"]; ok {
		t.Fatal("rrset not deleted")
	}
}

func TestCleanUpToleratesMissing(t *testing.T) {
	solver, _ := setup(t, map[string][]string{})
	if err := solver.CleanUp(challenge("_acme-challenge.asobi.dev.", "k1")); err != nil {
		t.Fatal(err)
	}
}

func TestCleanUpLeavesOtherKeysAlone(t *testing.T) {
	solver, api := setup(t, map[string][]string{"_acme-challenge": {`"other"`}})
	if err := solver.CleanUp(challenge("_acme-challenge.asobi.dev.", "k1")); err != nil {
		t.Fatal(err)
	}
	if got := api.rrsets["_acme-challenge"]; !slices.Equal(got, []string{`"other"`}) {
		t.Fatalf("records = %v", got)
	}
}

func TestRefusesNonChallengeNames(t *testing.T) {
	for _, fqdn := range []string{"asobi.dev.", "www.asobi.dev.", "x._acme-challenge.asobi.dev.", "_acme-challenge.example.com."} {
		solver, api := setup(t, map[string][]string{})
		if err := solver.Present(challenge(fqdn, "k1")); err == nil {
			t.Errorf("%s: Present succeeded", fqdn)
		}
		if err := solver.CleanUp(challenge(fqdn, "k1")); err == nil {
			t.Errorf("%s: CleanUp succeeded", fqdn)
		}
		if len(api.rrsets) != 0 {
			t.Errorf("%s: wrote %v", fqdn, api.rrsets)
		}
	}
}

func TestConfigErrors(t *testing.T) {
	cases := map[string]*extapi.JSON{
		"nil":         nil,
		"invalid":     {Raw: []byte(`{`)},
		"no name":     {Raw: []byte(`{"apiKeySecretRef":{"key":"token"}}`)},
		"no key":      {Raw: []byte(`{"apiKeySecretRef":{"name":"desec-token"}}`)},
		"no secret":   {Raw: []byte(`{"apiKeySecretRef":{"name":"missing","key":"token"}}`)},
		"missing key": {Raw: []byte(`{"apiKeySecretRef":{"name":"desec-token","key":"other"}}`)},
	}
	for name, cfg := range cases {
		solver, api := setup(t, map[string][]string{})
		ch := challenge("_acme-challenge.asobi.dev.", "k1")
		ch.Config = cfg
		if err := solver.Present(ch); err == nil {
			t.Errorf("%s: Present succeeded", name)
		}
		if len(api.calls) != 0 {
			t.Errorf("%s: called deSEC %v", name, api.calls)
		}
	}
}

func TestAPIErrorsSurface(t *testing.T) {
	solver, _ := setup(t, map[string][]string{})
	solver.client = fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "desec-token", Namespace: namespace},
		Data:       map[string][]byte{"token": []byte("revoked")},
	})
	if err := solver.Present(challenge("_acme-challenge.asobi.dev.", "k1")); err == nil {
		t.Fatal("Present succeeded with a rejected token")
	}
}
