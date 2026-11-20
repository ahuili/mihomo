package process

import "testing"

func TestUniqueUDPPathAgreement(t *testing.T) {
	var owner uniqueUDPPath
	if !owner.add("/fixture/one", nil) || !owner.add("/fixture/one", nil) ||
		owner.add("/fixture/two", nil) || owner.add("/fixture/one", ErrNotFound) ||
		owner.add("", nil) {
		t.Fatal("ambiguous or unavailable UDP owner accepted")
	}
}
