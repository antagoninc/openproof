package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

func rejects(b []byte) (bad bool) { defer func() { bad = recover() != nil }(); parse(b); return false }
func TestStrictJSON(t *testing.T) {
	for _, s := range []string{`{"a":1,"a":2}`, `{"a":1.0}`, `{"a":-1}`, `{"a":18446744073709551616}`, `{"a":"\ud800"}`, `{"a":"\udc00"}`, `[] []`} {
		if !rejects([]byte(s)) {
			t.Fatal(s)
		}
	}
	if rejects([]byte(`{"a":"\ud83d\ude00","b":18446744073709551615}`)) {
		t.Fatal("valid pair/u64 rejected")
	}
}
func TestOriginalCanonicalVectors(t *testing.T) {
	for input, want := range map[string]string{`null`: "4f5045430100", `"a"`: "4f5045430104000000000000000161", `1`: "4f50454301030000000000000001", `{"b":true,"a":null}`: "4f5045430106000000000000000204000000000000000161000400000000000000016202"} {
		if got := hex.EncodeToString(canonical(parse([]byte(input)))); got != want {
			t.Fatalf("%s: %s", input, got)
		}
	}
}
func TestWeakPoint(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("identity accepted")
		}
	}()
	key("01" + strings.Repeat("0", 62))
}
