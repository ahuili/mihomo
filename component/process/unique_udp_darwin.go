package process

import "path/filepath"

// Multiple candidate sockets are admissible only when their executable path
// agrees; looking up the last wildcard socket does not establish its owner.
type uniqueUDPPath struct{ path string }

func (owner *uniqueUDPPath) add(path string, err error) bool {
	if err != nil || !filepath.IsAbs(path) || (owner.path != "" && owner.path != path) {
		return false
	}
	owner.path = path
	return true
}
