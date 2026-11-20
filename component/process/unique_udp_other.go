//go:build !darwin

package process

import "net/netip"

// Haven's scoped TUN attribution is implemented for Darwin.
func FindUniqueSocketPath(network string, ip netip.Addr, port int) (string, error) {
	return "", ErrNotFound
}
