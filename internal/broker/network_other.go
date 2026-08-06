//go:build !linux

package broker

import (
	"context"
	"errors"
)

type Kernel interface {
	Apply(context.Context, Settings, WarpAccount, []Tunnel) ([]Tunnel, error)
	Inspect(Settings, WarpAccount, []Tunnel) ([]string, error)
	Remove(Settings, Tunnel) error
	TestWarp(context.Context, Settings, WarpAccount) (string, error)
}
type LinuxKernel struct{ DryRun bool }

func (k *LinuxKernel) Apply(_ context.Context, _ Settings, _ WarpAccount, t []Tunnel) ([]Tunnel, error) {
	if k.DryRun {
		return t, nil
	}
	return nil, errors.New("kernel networking is supported only on Linux")
}
func (k *LinuxKernel) Remove(_ Settings, _ Tunnel) error {
	if k.DryRun {
		return nil
	}
	return errors.New("kernel networking is supported only on Linux")
}
func (k *LinuxKernel) Inspect(_ Settings, _ WarpAccount, _ []Tunnel) ([]string, error) {
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
