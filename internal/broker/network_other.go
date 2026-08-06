//go:build !linux

package broker

import (
	"context"
	"errors"
)

type Kernel interface {
	Apply(context.Context, Settings, []Tunnel) ([]Tunnel, error)
	Inspect(Settings, []Tunnel) ([]string, error)
	Remove(Settings, Tunnel) error
}
type LinuxKernel struct{ DryRun bool }

func (k *LinuxKernel) Apply(_ context.Context, _ Settings, t []Tunnel) ([]Tunnel, error) {
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
func (k *LinuxKernel) Inspect(_ Settings, _ []Tunnel) ([]string, error) {
	if k.DryRun {
		return nil, nil
	}
	return nil, errors.New("kernel networking is supported only on Linux")
}
