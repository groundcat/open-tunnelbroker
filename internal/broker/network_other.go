//go:build !linux

package broker

import (
	"context"
	"errors"
	"log"
)

type Kernel interface {
	Apply(context.Context, Settings, WarpAccount, []Upstream, []Tunnel) ([]Tunnel, error)
	Inspect(Settings, WarpAccount, []Upstream, []Tunnel) ([]string, error)
	Remove(Upstream, Tunnel) error
	RemoveUpstream(Upstream) error
	TestWarp(context.Context, Settings, WarpAccount) (string, error)
	Close() error
}
type LinuxKernel struct {
	DryRun bool
	Logger *log.Logger
}

func (k *LinuxKernel) Close() error { return nil }

func (k *LinuxKernel) Apply(_ context.Context, _ Settings, _ WarpAccount, _ []Upstream, t []Tunnel) ([]Tunnel, error) {
	if k.DryRun {
		return t, nil
	}
	return nil, errors.New("kernel networking is supported only on Linux")
}
func (k *LinuxKernel) Remove(_ Upstream, _ Tunnel) error {
	if k.DryRun {
		return nil
	}
	return errors.New("kernel networking is supported only on Linux")
}
func (k *LinuxKernel) RemoveUpstream(_ Upstream) error {
	if k.DryRun {
		return nil
	}
	return errors.New("kernel networking is supported only on Linux")
}
func (k *LinuxKernel) Inspect(_ Settings, _ WarpAccount, _ []Upstream, _ []Tunnel) ([]string, error) {
	if k.DryRun {
		return nil, nil
	}
	return nil, errors.New("kernel networking is supported only on Linux")
}
func (k *LinuxKernel) TestWarp(_ context.Context, _ Settings, _ WarpAccount) (string, error) {
	if k.DryRun {
		return "fl=test\nip=203.0.113.8\nwarp=on\n", nil
	}
	return "", errors.New("kernel networking is supported only on Linux")
}
