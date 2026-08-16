//go:build linux

package vpn

import (
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
)

func (r *RealTun) Configure(ipCIDR string) error {
	name := r.ifce.Name()
	fmt.Printf("🔧 [RealTUN] Configuring interface %s via Netlink\n", name)

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	addr, err := netlink.ParseAddr(ipCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR %s: %w", ipCIDR, err)
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add IP address %s to %s: %w", ipCIDR, name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set interface %s up: %w", name, err)
	}

	return nil
}

func (r *RealTun) AddRoute(subnetCIDR string) error {
	name := r.ifce.Name()
	fmt.Printf("🔧 [RealTUN] Adding route %s dev %s via Netlink\n", subnetCIDR, name)

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	_, ipNet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse route CIDR %s: %w", subnetCIDR, err)
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipNet,
	}

	if err := netlink.RouteAdd(route); err != nil {
		if strings.Contains(err.Error(), "file exists") {
			return nil
		}
		return fmt.Errorf("failed to add route %s: %w", subnetCIDR, err)
	}
	return nil
}

func (r *RealTun) DeleteRoute(subnetCIDR string) error {
	name := r.ifce.Name()
	fmt.Printf("🔧 [RealTUN] Deleting route %s dev %s via Netlink\n", subnetCIDR, name)

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	_, ipNet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse route CIDR %s: %w", subnetCIDR, err)
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipNet,
	}

	if err := netlink.RouteDel(route); err != nil {
		if strings.Contains(err.Error(), "no such process") || strings.Contains(err.Error(), "no such route") {
			return nil
		}
		return fmt.Errorf("failed to delete route %s: %w", subnetCIDR, err)
	}
	return nil
}
