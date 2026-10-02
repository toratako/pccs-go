// Copyright (C) 2026 toratako and contributors
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/toratako/pccs-go/internal/service"
)

const sgxPrefix = "/sgx/certification/v4/"

type fakeBackend struct {
	response                                       service.Response
	err                                            error
	checkErr                                       error
	panicValue                                     any
	calls, checks                                  int
	product, endpoint, update, source, kind, fmspc string
	query                                          url.Values
	platform                                       service.Platform
	platforms                                      []service.Platform
	body                                           []byte
	policyID, policies                             string
}

func (f *fakeBackend) operation() error {
	f.calls++
	if f.panicValue != nil {
		panic(f.panicValue)
	}
	return f.err
}
func (f *fakeBackend) Get(_ context.Context, product, endpoint string, query url.Values) (service.Response, error) {
	f.product, f.endpoint, f.query = product, endpoint, query
	return f.response, f.operation()
}
func (f *fakeBackend) Register(_ context.Context, platform service.Platform, update string) error {
	f.platform, f.update = platform, update
	return f.operation()
}
func (f *fakeBackend) Platforms(_ context.Context, source string) ([]service.Platform, error) {
	f.source = source
	return f.platforms, f.operation()
}
func (f *fakeBackend) Import(_ context.Context, body []byte) error {
	f.body = body
	return f.operation()
}
func (f *fakeBackend) Refresh(_ context.Context, kind, fmspc string) error {
	f.kind, f.fmspc = kind, fmspc
	return f.operation()
}
func (f *fakeBackend) PutPolicy(_ context.Context, body []byte) (string, error) {
	f.body = body
	return f.policyID, f.operation()
}
func (f *fakeBackend) Policies(_ context.Context, fmspc string) (string, error) {
	f.fmspc = fmspc
	return f.policies, f.operation()
}
func (f *fakeBackend) Check() error { f.checks++; return f.checkErr }

func TestAdministrativeHEADDoesNotChangeState(t *testing.T) {
	for _, endpoint := range []string{"platforms", "refresh"} {
		backend := &fakeBackend{}
		response := request(testHandler(t, backend), "HEAD", sgxPrefix+endpoint, "", "Admin-Token", "admin-secret")
		if response.Code != http.StatusMethodNotAllowed || backend.calls != 0 || response.Body.Len() != 0 {
			t.Fatalf("HEAD must reject administrative mutations: status=%d calls=%d", response.Code, backend.calls)
		}
	}
}

func tokenHash(token string) string {
	digest := sha512.Sum512([]byte(token))
	return hex.EncodeToString(digest[:])
}

func testHandler(t *testing.T, f *fakeBackend) http.Handler {
	t.Helper()
	h, err := New(Config{UserTokenHash: tokenHash("user-secret"), AdminTokenHash: tokenHash("admin-secret")}, f, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func request(h http.Handler, method, path, body, header, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if header != "" {
		r.Header.Set(header, token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestNewConfiguration(t *testing.T) {
	for _, cfg := range []Config{{MaxBodyBytes: -1}, {UserTokenHash: "secret"}, {AdminTokenHash: strings.Repeat("z", 128)}, {AdminTokenHash: strings.Repeat("a", 126)}} {
		if _, err := New(cfg, &fakeBackend{}, nil); err == nil {
			t.Errorf("accepted invalid config %+v", cfg)
		}
	}
	if _, err := New(Config{}, nil, nil); err == nil {
		t.Fatal("accepted nil backend")
	}
	if _, err := New(Config{UserTokenHash: strings.ToUpper(tokenHash("user"))}, &fakeBackend{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestAuthentication(t *testing.T) {
	registration := `{"qe_id":"id","pce_id":"0000","platform_manifest":"manifest"}`
	cases := []struct {
		method, endpoint, body, header, token string
		status                                int
	}{
		{"POST", "platforms", registration, "User-Token", "user-secret", 200},
		{"POST", "platforms", registration, "User-Token", "wrong", 401},
		{"POST", "platforms", registration, "Admin-Token", "admin-secret", 401},
		{"POST", "platforms", registration, "", "", 401},
		{"GET", "platforms", "", "Admin-Token", "admin-secret", 200},
		{"GET", "platforms", "", "User-Token", "user-secret", 401},
		{"PUT", "platformcollateral", `{"platforms":[],"collaterals":{}}`, "Admin-Token", "admin-secret", 200},
		{"PUT", "platformcollateral", `{}`, "", "", 401},
		{"POST", "refresh", "", "Admin-Token", "admin-secret", 200},
		{"GET", "refresh", "", "", "", 401},
		{"PUT", "appraisalpolicy", `{"is_default":false,"fmspc":"001122334455","policy":"jwt"}`, "Admin-Token", "admin-secret", 200},
		{"PUT", "appraisalpolicy", `{}`, "", "", 401},
		{"GET", "appraisalpolicy?fmspc=001122334455", "", "", "", 200},
		{"GET", "qe/identity", "", "", "", 200},
	}
	for _, tc := range cases {
		t.Run(tc.method+"/"+tc.endpoint+"/"+tc.header+"/"+tc.token, func(t *testing.T) {
			f := &fakeBackend{policies: "jwt"}
			w := request(testHandler(t, f), tc.method, sgxPrefix+tc.endpoint, tc.body, tc.header, tc.token)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if tc.status == 401 && f.calls != 0 {
				t.Fatal("unauthenticated backend call")
			}
		})
	}
	for _, method := range []string{"POST", "GET"} {
		f := &fakeBackend{}
		h, err := New(Config{}, f, nil)
		if err != nil {
			t.Fatal(err)
		}
		w := request(h, method, sgxPrefix+"platforms", registration, "User-Token", "user-secret")
		if w.Code != 401 || f.calls != 0 {
			t.Fatal("unset token hash did not deny access")
		}
	}
	f := &fakeBackend{}
	r := httptest.NewRequest("GET", sgxPrefix+"platforms", nil)
	r.Header.Add("Admin-Token", "admin-secret")
	r.Header.Add("Admin-Token", "admin-secret")
	w := httptest.NewRecorder()
	testHandler(t, f).ServeHTTP(w, r)
	if w.Code != 401 || f.calls != 0 {
		t.Fatal("duplicate authentication header accepted")
	}
}

func TestRoutesAndMethods(t *testing.T) {
	paths := []string{
		sgxPrefix + "pckcert?qeid=qe&cpusvn=" + strings.Repeat("a", 32) + "&pcesvn=0000&pceid=0000",
		sgxPrefix + "pckcrl?ca=processor", sgxPrefix + "tcb?fmspc=001122334455",
		sgxPrefix + "qe/identity", sgxPrefix + "qve/identity", sgxPrefix + "rootcacrl",
		sgxPrefix + "crl?uri=" + url.QueryEscape("https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl"),
		"/tdx/certification/v4/tcb?fmspc=001122334455", "/tdx/certification/v4/qe/identity",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			f := &fakeBackend{response: service.Response{Body: []byte("data")}}
			w := request(testHandler(t, f), "GET", path, "", "", "")
			if w.Code != 200 || f.calls != 1 {
				t.Fatalf("route failed: %d %s", w.Code, w.Body.String())
			}
			product := "sgx"
			if strings.HasPrefix(path, "/tdx/") {
				product = "tdx"
			}
			if f.product != product {
				t.Fatalf("product %s", f.product)
			}
			w = request(testHandler(t, f), "DELETE", path, "", "", "")
			if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" || f.calls != 1 {
				t.Fatal("incorrect method handling")
			}
		})
	}
	for _, path := range []string{"/", sgxPrefix + "unknown", sgxPrefix + "qe/identity/", "/tdx/certification/v4/pckcert", "/healthz/unknown"} {
		f := &fakeBackend{}
		w := request(testHandler(t, f), "GET", path, "", "", "")
		if w.Code != 404 || f.calls != 0 {
			t.Fatalf("unknown route %s returned %d", path, w.Code)
		}
	}
	for _, path := range []string{"/sgx/certification/v3/pckcert", "/tdx/certification/v3/tcb"} {
		w := request(testHandler(t, &fakeBackend{}), "GET", path, "", "", "")
		if w.Code != 410 {
			t.Fatalf("v3 returned %d", w.Code)
		}
	}
	for _, tc := range []struct{ endpoint, allow string }{{"platforms", "GET, POST"}, {"refresh", "GET, POST"}, {"platformcollateral", "PUT"}, {"appraisalpolicy", "GET, HEAD, PUT"}} {
		w := request(testHandler(t, &fakeBackend{}), "PATCH", sgxPrefix+tc.endpoint, "", "", "")
		if w.Code != 405 || w.Header().Get("Allow") != tc.allow {
			t.Fatalf("allow %s", tc.endpoint)
		}
	}
}

func TestQueryValidationAndNormalization(t *testing.T) {
	badPaths := []string{
		"pckcert", "pckcert?qeid=qe&cpusvn=00&pcesvn=0000&pceid=0000",
		"pckcert?qeid=" + strings.Repeat("a", 261) + "&cpusvn=" + strings.Repeat("0", 32) + "&pcesvn=0000&pceid=0000",
		"pckcert?qeid=qe&cpusvn=" + strings.Repeat("0", 32) + "&pcesvn=0000&pceid=0000&encrypted_ppid=",
		"pckcrl", "pckcrl?ca=unknown", "tcb", "tcb?fmspc=00112233445z", "tcb?fmspc=001122334455&update=all",
		"qe/identity?update=", "qe/identity?update=invalid", "qe/identity?update=early&update=standard",
		"qe/identity?ignored=a&ignored=b", "qe/identity?bad=%zz", "crl?uri=https://example.com/a.crl",
		"platforms?source=unknown", "platforms?source=[bad]", "refresh?type=other", "refresh?type=certs",
		"refresh?type=certs&fmspc=00000000000z", "appraisalpolicy?fmspc=00",
	}
	for _, path := range badPaths {
		t.Run(path, func(t *testing.T) {
			f := &fakeBackend{}
			w := request(testHandler(t, f), "GET", sgxPrefix+path, "", "Admin-Token", "admin-secret")
			if w.Code != 400 || f.calls != 0 {
				t.Fatalf("got %d calls=%d", w.Code, f.calls)
			}
		})
	}
	f := &fakeBackend{}
	w := request(testHandler(t, f), "GET", sgxPrefix+"tcb?fmspc=aabbccddeeff&update=EARLY&secret=ignored", "", "", "")
	if w.Code != 200 || f.query.Get("fmspc") != "AABBCCDDEEFF" || f.query.Get("update") != "early" || len(f.query) != 2 {
		t.Fatalf("query normalization: %v", f.query)
	}
	w = request(testHandler(t, f), "GET", sgxPrefix+"pckcert?qeid=nonhex-id&cpusvn="+strings.Repeat("a", 32)+"&pcesvn=aabb&pceid=ccdd", "", "", "")
	if w.Code != 200 || f.query.Get("qeid") != "NONHEX-ID" || f.query.Get("cpusvn") != strings.Repeat("A", 32) {
		t.Fatalf("pckcert normalized query: %v", f.query)
	}
	w = request(testHandler(t, f), "GET", sgxPrefix+"platforms?source=[aabbccddeeff,001122334455]", "", "Admin-Token", "admin-secret")
	if w.Code != 200 || f.source != "[AABBCCDDEEFF,001122334455]" {
		t.Fatalf("source %s", f.source)
	}
	w = request(testHandler(t, f), "POST", sgxPrefix+"refresh?type=certs&fmspc=all", "", "Admin-Token", "admin-secret")
	if w.Code != 200 || f.kind != "certs" || f.fmspc != "all" {
		t.Fatal("refresh all not accepted")
	}
}

func TestBoundedStrictBodies(t *testing.T) {
	badBodies := []string{
		``, `null`, `[]`, `{"qe_id":"id","pce_id":"0000"} {}`,
		`{"qe_id":"a","qe_id":"b","pce_id":"0000"}`, `{"qe_id":"id","pce_id":"0000","unknown":"x"}`,
		`{"qe_id":null,"pce_id":"0000"}`, `{"qe_id":3,"pce_id":"0000"}`, `{"qe_id":"id","pce_id":"0"}`,
		`{"qe_id":"id","pce_id":"0000","cpu_svn":null}`, `{"qe_id":"id","pce_id":"0000","enc_ppid":""}`,
	}
	for _, body := range badBodies {
		t.Run(body, func(t *testing.T) {
			f := &fakeBackend{}
			r := httptest.NewRequest("POST", sgxPrefix+"platforms", strings.NewReader(body))
			r.Header.Set("User-Token", "user-secret")
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			testHandler(t, f).ServeHTTP(w, r)
			if w.Code != 400 || f.calls != 0 {
				t.Fatalf("status %d calls=%d", w.Code, f.calls)
			}
		})
	}
	f := &fakeBackend{}
	w := request(testHandler(t, f), "POST", sgxPrefix+"platforms?update=ALL", `{"qe_id":"id","pce_id":"aabb","platform_manifest":null}`, "User-Token", "user-secret")
	if w.Code != 200 || f.update != "all" || f.platform.QEID != "ID" || f.platform.PCEID != "AABB" || f.platform.PlatformManifest != "" {
		t.Fatalf("registration mismatch: %+v", f.platform)
	}
	for _, endpoint := range []string{"platformcollateral", "appraisalpolicy"} {
		f := &fakeBackend{}
		w := request(testHandler(t, f), "PUT", sgxPrefix+endpoint, `{"nested":{"x":1,"x":2}}`, "Admin-Token", "admin-secret")
		if w.Code != 400 || f.calls != 0 {
			t.Fatal("nested duplicate key accepted")
		}
	}
	for _, knownLength := range []bool{true, false} {
		f := &fakeBackend{}
		h, err := New(Config{UserTokenHash: tokenHash("user-secret"), MaxBodyBytes: 32}, f, nil)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", sgxPrefix+"platforms", strings.NewReader(`{"qe_id":"`+strings.Repeat("a", 80)+`","pce_id":"0000"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("User-Token", "user-secret")
		if !knownLength {
			r.ContentLength = -1
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 413 || f.calls != 0 {
			t.Fatalf("limit returned %d", w.Code)
		}
	}
	f = &fakeBackend{}
	r := httptest.NewRequest("POST", sgxPrefix+"platforms", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("User-Token", "user-secret")
	w = httptest.NewRecorder()
	testHandler(t, f).ServeHTTP(w, r)
	if w.Code != 415 || f.calls != 0 {
		t.Fatal("non-JSON body accepted")
	}
	for _, body := range []string{`{"is_default":true,"fmspc":"001122334455"}`, `{"is_default":"false","fmspc":"001122334455","policy":"jwt"}`, `{"is_default":false,"fmspc":"bad","policy":"jwt"}`, `{"is_default":false,"fmspc":"001122334455","policy":"jwt","unknown":1}`} {
		f := &fakeBackend{}
		w := request(testHandler(t, f), "PUT", sgxPrefix+"appraisalpolicy", body, "Admin-Token", "admin-secret")
		if w.Code != 400 || f.calls != 0 {
			t.Fatalf("policy invalid body: %s", body)
		}
	}
}

func TestCollateralHeadersAndHEAD(t *testing.T) {
	f := &fakeBackend{response: service.Response{Body: []byte{0, 1, 2, 3}, Header: http.Header{
		"Content-Type": {"application/pkix-crl"}, "Sgx-Pck-Crl-Issuer-Chain": {"encoded-chain"}, "Admin-Token": {"secret"}, "Set-Cookie": {"secret"}, "Request-Id": {"caller"},
	}}}
	h := testHandler(t, f)
	for _, method := range []string{"GET", "HEAD"} {
		w := request(h, method, sgxPrefix+"pckcrl?ca=PLATFORM&encoding=DER", "", "", "")
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/pkix-crl" || w.Header().Get("SGX-PCK-CRL-Issuer-Chain") != "encoded-chain" || w.Header().Get("Content-Length") != "4" {
			t.Fatalf("headers %v", w.Header())
		}
		if w.Header().Get("Admin-Token") != "" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Request-ID") == "caller" {
			t.Fatal("nonpublic backend headers copied")
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("common response headers missing")
		}
		if f.query.Get("ca") != "platform" || f.query.Get("encoding") != "der" {
			t.Fatal("CRL parameters not normalized")
		}
		if method == "HEAD" && w.Body.Len() != 0 || method == "GET" && !bytes.Equal(w.Body.Bytes(), f.response.Body) {
			t.Fatal("incorrect response body")
		}
	}
	w := request(h, "GET", sgxPrefix+"platforms", "", "Admin-Token", "admin-secret")
	if w.Header().Get("Platform-Count") != "0" || w.Body.String() != "[]" {
		t.Fatalf("nil platforms %s", w.Body.String())
	}
}

func TestJSONContainerValidation(t *testing.T) {
	for _, body := range []string{`{}`, `{"a":[1,"str",null,true,false,{},[2]]}`, `{"a":{"b":1},"b":{"b":2}}`} {
		if !strictObject([]byte(body)) {
			t.Errorf("rejected JSON object: %s", body)
		}
	}
	for _, body := range []string{`{"a":}`, `{"a":[1,]}`, `{"a":{"b":1,"b":2}}`, `{} garbage`, `{"x":` + strings.Repeat("[", 64) + `0` + strings.Repeat("]", 64) + `}`} {
		if strictObject([]byte(body)) {
			t.Errorf("accepted invalid JSON object: %s", body)
		}
	}
}

func TestHealthChecks(t *testing.T) {
	for _, failure := range []bool{false, true} {
		for _, probe := range []string{"live", "ready", "startup"} {
			t.Run(fmt.Sprintf("%s/failure=%v", probe, failure), func(t *testing.T) {
				f := &fakeBackend{}
				if failure {
					f.checkErr = errors.New("database-user-secret")
				}
				w := request(testHandler(t, f), "GET", "/healthz/"+probe, "", "", "")
				want := 200
				if failure && probe != "live" {
					want = 503
				}
				if w.Code != want {
					t.Fatalf("health status %d", w.Code)
				}
				var body map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body["timestamp"] == "" {
					t.Fatal("timestamp missing")
				}
				if probe == "live" && f.checks != 0 || probe != "live" && f.checks != 1 {
					t.Fatal("incorrect database check count")
				}
				if strings.Contains(w.Body.String(), "database-user-secret") {
					t.Fatal("database details disclosed")
				}
				if probe == "ready" && failure && (body["status"] != "DOWN" || body["db"] != "DISCONNECTED") {
					t.Fatal("readiness failure missing")
				}
				if probe == "startup" && !failure && body["status"] != "STARTED" {
					t.Fatal("startup state missing")
				}
			})
		}
	}
}

func TestErrorsRecoveryAndSafeLogging(t *testing.T) {
	for _, backendError := range []error{errors.New("internal-secret"), &service.StatusError{StatusCode: 460, Message: "internal-secret"}, &service.StatusError{StatusCode: 999, Message: "internal-secret"}} {
		var logs bytes.Buffer
		f := &fakeBackend{err: backendError}
		h, err := New(Config{}, f, slog.New(slog.NewJSONHandler(&logs, nil)))
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", sgxPrefix+"qe/identity?secret=query-secret", nil)
		r.Header.Set("User-Token", "token-secret")
		r.Header.Set("Request-ID", "request-secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 500
		var statusError *service.StatusError
		if errors.As(backendError, &statusError) && statusError.StatusCode == 460 {
			want = 460
		}
		if w.Code != want {
			t.Fatalf("status %d want %d", w.Code, want)
		}
		for _, secret := range []string{"internal-secret", "query-secret", "token-secret", "request-secret"} {
			if strings.Contains(logs.String()+w.Body.String()+fmt.Sprint(w.Header()), secret) {
				t.Fatalf("secret disclosed: %s", secret)
			}
		}
		id := w.Header().Get("Request-ID")
		if len(id) != 32 {
			t.Fatalf("request ID %q", id)
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(logs.String(), id) {
			t.Fatal("request ID absent from log")
		}
	}
	var logs bytes.Buffer
	f := &fakeBackend{panicValue: "panic-secret"}
	h, err := New(Config{}, f, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	w := request(h, "GET", sgxPrefix+"qe/identity", "", "", "")
	if w.Code != 500 || strings.Contains(logs.String()+w.Body.String(), "panic-secret") {
		t.Fatal("panic not handled safely")
	}
	w = request(h, "GET", "/unknown-path-secret?secret=query-secret", "", "", "")
	if w.Code != 404 || strings.Contains(logs.String(), "unknown-path-secret") || strings.Contains(logs.String(), "query-secret") {
		t.Fatal("unknown path included in logs")
	}
}
