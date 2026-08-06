package broker

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type UpgradeStatus struct {
	Available          bool
	Repository, Remote string
	Branch, Revision   string
	State, Detail      string
}

type Upgrader interface {
	Status(context.Context) UpgradeStatus
	Start(context.Context) error
}

type SystemUpgrader struct {
	repository, service, statusPath string
}

func NewSystemUpgrader() *SystemUpgrader {
	repository := strings.TrimSpace(os.Getenv("OTB_UPGRADE_REPO"))
	if repository == "" {
		if cwd, err := os.Getwd(); err == nil {
			repository = cwd
		}
	}
	service := strings.TrimSpace(os.Getenv("OTB_UPGRADE_SERVICE"))
	if service == "" {
		service = "open-tunnelbroker-upgrade.service"
	}
	statusPath := strings.TrimSpace(os.Getenv("OTB_UPGRADE_STATUS"))
	if statusPath == "" {
		statusPath = "/var/lib/open-tunnelbroker/upgrade-status"
	}
	return &SystemUpgrader{repository: repository, service: service, statusPath: statusPath}
}

func (u *SystemUpgrader) Status(ctx context.Context) UpgradeStatus {
	status := UpgradeStatus{Repository: u.repository, State: "never run"}
	if output, err := os.ReadFile(u.statusPath); err == nil {
		lines := strings.SplitN(strings.TrimSpace(string(output)), "\n", 2)
		if len(lines) > 0 && lines[0] != "" {
			status.State = lines[0]
		}
		if len(lines) > 1 {
			status.Detail = lines[1]
		}
	}
	if u.repository == "" || !filepath.IsAbs(u.repository) {
		status.Detail = "configure OTB_UPGRADE_REPO with an absolute Git checkout path"
		return status
	}
	remote, err := gitOutput(ctx, u.repository, "remote", "get-url", "origin")
	if err != nil {
		status.Detail = "upgrade repository is unavailable: " + err.Error()
		return status
	}
	status.Remote = redactRemote(remote)
	status.Branch, _ = gitOutput(ctx, u.repository, "branch", "--show-current")
	status.Revision, _ = gitOutput(ctx, u.repository, "rev-parse", "--short=12", "HEAD")
	status.Available = status.Branch != "" && status.Revision != ""
	return status
}

func redactRemote(remote string) string {
	parsed, err := url.Parse(remote)
	if err != nil || parsed.User == nil {
		return remote
	}
	parsed.User = url.User("redacted")
	return parsed.String()
}

func gitOutput(parent context.Context, repository string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	commandArgs := append([]string{"-C", repository}, args...)
	output, err := exec.CommandContext(ctx, "git", commandArgs...).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return "", errors.New(message)
	}
	return strings.TrimSpace(string(output)), nil
}

func (u *SystemUpgrader) Start(ctx context.Context) error {
	if !u.Status(ctx).Available {
		return errors.New("upgrade repository is not configured or is unavailable")
	}
	command := exec.CommandContext(ctx, "systemctl", "start", "--no-block", u.service)
	if output, err := command.CombinedOutput(); err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return errors.New(message)
	}
	return nil
}

func (a *App) StartUpgrade(ctx context.Context, admin string) error {
	if a.upgrader == nil {
		return errors.New("upgrade service is unavailable")
	}
	if err := a.upgrader.Start(ctx); err != nil {
		return err
	}
	_ = a.store.AddAudit(admin, "upgrade", "system upgrade requested")
	return nil
}
