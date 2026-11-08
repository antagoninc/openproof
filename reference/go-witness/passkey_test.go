package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

const testOrigin = "http://localhost:8765"

var testDigest = strings.Repeat("ab", 32)

type parts struct {
	rp        string
	flags     byte
	kind      string
	origin    string
	challenge string
	extra     string
}

func goodParts() parts {
	raw, _ := hex.DecodeString(testDigest)
	return parts{"localhost", 0x05, "webauthn.get", testOrigin, base64.RawURLEncoding.EncodeToString(raw), ""}
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return k
}

func pointHex(k *ecdsa.PrivateKey) string {
	raw := make([]byte, 65)
	raw[0] = 4
	k.X.FillBytes(raw[1:33])
	k.Y.FillBytes(raw[33:])
	return hex.EncodeToString(raw)
}

func testTrust(k *ecdsa.PrivateKey, from int) map[string]any {
	text := fmt.Sprintf(`{"owner_passkey":{"public_key":"%s","rp_id":"localhost","origin":"%s","from_sequence":%d}}`, pointHex(k), testOrigin, from)
	return obj(parse([]byte(text)))
}

func testAssertion(t *testing.T, k *ecdsa.PrivateKey, p parts) map[string]any {
	client := fmt.Sprintf(`{"type":"%s","challenge":"%s","origin":"%s"%s}`, p.kind, p.challenge, p.origin, p.extra)
	rp := sha256.Sum256([]byte(p.rp))
	auth := append(rp[:], p.flags, 0, 0, 0, 0)
	clientHash := sha256.Sum256([]byte(client))
	signed := sha256.Sum256(append(append([]byte{}, auth...), clientHash[:]...))
	sig, e := ecdsa.SignASN1(rand.Reader, k, signed[:])
	if e != nil {
		t.Fatal(e)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]any{"authenticator_data": enc(auth), "client_data_json": enc([]byte(client)), "signature": enc(sig)}
}

func accepts(q, tr map[string]any, sequence uint64) (ok bool) {
	defer func() { ok = recover() == nil }()
	ownerAssertion(q, tr, testDigest, sequence)
	return true
}

func TestPasskeyAssertion(t *testing.T) {
	k := testKey(t)
	tr := testTrust(k, 1)
	ownerPasskey(tr["owner_passkey"])
	with := func(a map[string]any) map[string]any { return map[string]any{"owner_assertion": a} }
	if !accepts(with(testAssertion(t, k, goodParts())), tr, 1) {
		t.Fatal("valid assertion rejected")
	}
	cross := goodParts()
	cross.extra = `,"crossOrigin":false`
	if !accepts(with(testAssertion(t, k, cross)), tr, 1) {
		t.Fatal("crossOrigin false rejected")
	}
	bad := map[string]func(*parts){
		"wrong challenge": func(p *parts) { p.challenge = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) },
		"wrong rp_id":     func(p *parts) { p.rp = "attacker.example" },
		"no UV":           func(p *parts) { p.flags = 0x01 },
		"no UP":           func(p *parts) { p.flags = 0x04 },
		"create type":     func(p *parts) { p.kind = "webauthn.create" },
		"wrong origin":    func(p *parts) { p.origin = "http://localhost:8766" },
		"cross origin":    func(p *parts) { p.extra = `,"crossOrigin":true` },
		"null cross":      func(p *parts) { p.extra = `,"crossOrigin":null` },
		"duplicate type":  func(p *parts) { p.extra = `,"type":"webauthn.get"` },
	}
	for name, change := range bad {
		p := goodParts()
		change(&p)
		if accepts(with(testAssertion(t, k, p)), tr, 1) {
			t.Fatal(name)
		}
	}
	good := testAssertion(t, k, goodParts())
	sig, _ := base64.RawURLEncoding.DecodeString(good["signature"].(string))
	sig[len(sig)-1] ^= 1
	garbled := map[string]any{"authenticator_data": good["authenticator_data"], "client_data_json": good["client_data_json"], "signature": base64.RawURLEncoding.EncodeToString(sig)}
	if accepts(with(garbled), tr, 1) {
		t.Fatal("bad signature accepted")
	}
	other := testAssertion(t, testKey(t), goodParts())
	if accepts(with(other), tr, 1) {
		t.Fatal("other key accepted")
	}
	padded := map[string]any{"authenticator_data": good["authenticator_data"], "client_data_json": good["client_data_json"], "signature": good["signature"].(string) + "="}
	if accepts(with(padded), tr, 1) {
		t.Fatal("padded base64 accepted")
	}
	huge := map[string]any{"authenticator_data": base64.RawURLEncoding.EncodeToString(make([]byte, 1025)), "client_data_json": good["client_data_json"], "signature": good["signature"]}
	if accepts(with(huge), tr, 1) {
		t.Fatal("oversize authenticator data accepted")
	}
	if accepts(map[string]any{}, tr, 1) {
		t.Fatal("missing assertion accepted when required")
	}
	if accepts(with(good), map[string]any{}, 1) {
		t.Fatal("assertion accepted without configured passkey")
	}
	if !accepts(map[string]any{}, map[string]any{}, 1) {
		t.Fatal("plain request rejected without passkey")
	}
	later := testTrust(k, 3)
	if !accepts(map[string]any{}, later, 2) || accepts(with(good), later, 2) || accepts(map[string]any{}, later, 3) || !accepts(with(good), later, 3) {
		t.Fatal("from_sequence boundary")
	}
}

func TestPasskeyConfiguration(t *testing.T) {
	k := testKey(t)
	good := `{"public_key":"%s","rp_id":"%s","origin":"%s","from_sequence":%s}`
	cases := []struct {
		point, rp, origin, from string
		ok                      bool
	}{
		{pointHex(k), "localhost", testOrigin, "1", true},
		{pointHex(k), "owner.example", "https://app.owner.example:8443", "1", true},
		{pointHex(k), "127.0.0.1", "http://localhost:8765", "1", false},
		{pointHex(k), "localhost", "http://127.0.0.1:8765", "1", false},
		{pointHex(k), "localhost", "http://localhost", "1", false},
		{pointHex(k), "localhost", "http://localhost:08765", "1", false},
		{pointHex(k), "localhost", testOrigin, "0", false},
		{"04" + strings.Repeat("11", 64), "localhost", testOrigin, "1", false},
		{strings.ToUpper(pointHex(k)), "localhost", testOrigin, "1", false},
	}
	for _, c := range cases {
		v := parse([]byte(fmt.Sprintf(good, c.point, c.rp, c.origin, c.from)))
		ok := func() (ok bool) {
			defer func() { ok = recover() == nil }()
			ownerPasskey(v)
			return true
		}()
		if ok != c.ok {
			t.Fatal(c)
		}
	}
}
