package broker

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeUpgrader struct {
	status  UpgradeStatus
	started bool
	err     error
}

func (f *fakeUpgrader) Status(context.Context) UpgradeStatus { return f.status }
func (f *fakeUpgrader) Start(context.Context) error {
	f.started = true
	return f.err
}

func TestSystemUpgraderReportsConfiguredRepository(t *testing.T) {
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(t.TempDir(), "status")
	if err = os.WriteFile(statusPath, []byte("succeeded\ndeployed test revision\n"), 0600); err != nil {
		t.Fatal(err)
	}
	upgrader := &SystemUpgrader{repository: repository, service: "test.service", statusPath: statusPath}
	status := upgrader.Status(context.Background())
	if !status.Available || status.Remote == "" || status.Branch == "" || status.Revision == "" || status.State != "succeeded" || status.Detail != "deployed test revision" {
		t.Fatalf("unexpected upgrade status: %+v", status)
	}
}

func TestUpgradeRemoteCredentialsAreRedacted(t *testing.T) {
	got := redactRemote("https://admin:secret-token@example.test/repo.git")
	if strings.Contains(got, "admin") || strings.Contains(got, "secret-token") || !strings.Contains(got, "redacted@") {
		t.Fatalf("remote credentials were exposed: %s", got)
	}
}

func TestUpgradePageStartsConfiguredUpgradeService(t *testing.T) {
	a, err := New(filepath.Join(t.TempDir(), "broker.db"), true, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	fake := &fakeUpgrader{status: UpgradeStatus{Available: true, Repository: "/opt/open-tunnelbroker", Remote: "https://example.test/repo.git", Branch: "main", Revision: "abc123", State: "never run"}}
	a.upgrader = fake

	get := httptest.NewRequest(http.MethodGet, "/upgrade", nil)
	get.Header.Set("X-OTB-User", "admin")
	get.Header.Set("X-OTB-CSRF", "token")
	getRecorder := httptest.NewRecorder()
	a.upgradeAction(getRecorder, get)
	if body := getRecorder.Body.String(); !containsAll(body, "Pull, test, and deploy latest", fake.status.Remote, fake.status.Revision) {
		t.Fatalf("upgrade page is incomplete: %s", body)
	}

	form := url.Values{"csrf": {"token"}}
	post := httptest.NewRequest(http.MethodPost, "/upgrade", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("X-OTB-User", "admin")
	post.Header.Set("X-OTB-CSRF", "token")
	postRecorder := httptest.NewRecorder()
	a.upgradeAction(postRecorder, post)
	if !fake.started || postRecorder.Code != http.StatusSeeOther {
		t.Fatalf("upgrade was not started: started=%v status=%d", fake.started, postRecorder.Code)
	}
}

func TestUpgradePostRequiresCSRF(t *testing.T) {
	a, _ := testApp(t)
	fake := &fakeUpgrader{status: UpgradeStatus{Available: true}}
	a.upgrader = fake
	request := httptest.NewRequest(http.MethodPost, "/upgrade", nil)
	request.Header.Set("X-OTB-CSRF", "expected-token")
	recorder := httptest.NewRecorder()
	a.upgradeAction(recorder, request)
	if recorder.Code != http.StatusBadRequest || fake.started {
		t.Fatalf("upgrade accepted without CSRF: status=%d started=%v", recorder.Code, fake.started)
	}
}
