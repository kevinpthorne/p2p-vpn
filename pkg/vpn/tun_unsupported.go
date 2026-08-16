//go:build !linux && !darwin && !windows

package vpn

import (
	"fmt"
)

func (r *RealTun) Configure(ipCIDR string) error {
	return fmt.Errorf("unsupported platform for auto-configuration")
}

func (r *RealTun) AddRoute(subnetCIDR string) error {
	return fmt.Errorf("unsupported platform for route configuration")
}

func (r *RealTun) DeleteRoute(subnetCIDR string) error {
	return fmt.Errorf("unsupported platform for route deletion")
}
