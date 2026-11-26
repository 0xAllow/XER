package main

import "net"

func localLANAddresses() []string {
	var found []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return found
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, e := iface.Addrs()
		if e != nil {
			continue
		}
		for _, a := range addrs {
			ip, _, e := net.ParseCIDR(a.String())
			if e == nil && ip.To4() != nil && ip.IsPrivate() {
				found = append(found, ip.String())
			}
		}
	}
	return found
}
