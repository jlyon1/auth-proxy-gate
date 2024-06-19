package auth

import "testing"

func TestLinkState_EncodeAndDecode(t *testing.T) {
	l := LinkState{
		Link: true,
		Rand: []byte("x"),
	}

	val, err := l.Encode()
	if err != nil {
		t.Error("Failed to encode linkstate unexpectedly")
	}

	s2 := LinkState{}

	err = s2.Decode(val)
	if err != nil {
		t.Error("Failed to decode")
	}

	if s2.Link != true {
		t.Error("result was unexpected")
	}

	if s2.Rand[0] == []byte("x")[0] {
		t.Error("bytes were not randomized")
	}
}
