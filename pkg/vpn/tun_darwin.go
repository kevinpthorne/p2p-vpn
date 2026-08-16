//go:build darwin

package vpn

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func (r *RealTun) Configure(ipCIDR string) error {
	ip, ipNet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", ipCIDR, err)
	}

	name := r.ifce.Name()
	var cmd *exec.Cmd

	mask := net.IP(ipNet.Mask).String()
	fmt.Printf("🔧 [RealTUN] Running: ifconfig %s %s %s netmask %s up\n", name, ip.String(), ip.String(), mask)
	cmd = exec.Command("ifconfig", name, ip.String(), ip.String(), "netmask", mask, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure ifconfig: %w", err)
	}

	subnetStr := ipNet.String()
	fmt.Printf("🔧 [RealTUN] Running: route add -net %s -interface %s\n", subnetStr, name)
	cmd = exec.Command("route", "add", "-net", subnetStr, "-interface", name)
	if err := cmd.Run(); err != nil {
		if !strings.Contains(err.Error(), "File exists") {
			return fmt.Errorf("failed to add subnet route on macOS: %w", err)
		}
	}

	return nil
}

func (r *RealTun) AddRoute(subnetCIDR string) error {
	name := r.ifce.Name()
	var cmd *exec.Cmd

	fmt.Printf("🔧 [RealTUN] Running: route add -net %s -interface %s\n", subnetCIDR, name)
	cmd = exec.Command("route", "add", "-net", subnetCIDR, "-interface", name)
	if err := cmd.Run(); err != nil {
		if strings.Contains(err.Error(), "File exists") {
			return nil
		}
		return fmt.Errorf("failed to add route: %w", err)
	}
	return nil
}

func (r *RealTun) DeleteRoute(subnetCIDR string) error {
	name := r.ifce.Name()
	var cmd *exec.Cmd

	fmt.Printf("🔧 [RealTUN] Running: route delete -net %s -interface %s\n", subnetCIDR, name)
	cmd = exec.Command("route", "delete", "-net", subnetCIDR, "-interface", name)
	if err := cmd.Run(); err != nil {
		if strings.Contains(err.Error(), "not in table") || strings.Contains(err.Error(), "exit status 1") {
			return nil
		}
		return fmt.Errorf("failed to delete route: %w", err)
	}
	return nil
}
