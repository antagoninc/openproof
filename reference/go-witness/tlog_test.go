package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func fails(f func()) (failed bool) {
	defer func() { failed = recover() != nil }()
	f()
	return false
}

func TestTreeRootRFC6962Vectors(t *testing.T) {
	data := []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"}
	var leaves [][32]byte
	for _, d := range data {
		b, _ := hex.DecodeString(d)
		leaves = append(leaves, leafHash(b))
	}
	r := treeRoot(leaves)
	if hex.EncodeToString(r[:]) != "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328" {
		t.Fatal("8-leaf root")
	}
	e := treeRoot(nil)
	if hex.EncodeToString(e[:]) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("empty root")
	}
}

func vkeyFor(name string, kind byte, pub []byte) string {
	return fmt.Sprintf("%s+%s+%s", name, hex.EncodeToString(noteKeyID(name, kind, pub)), base64.StdEncoding.EncodeToString(append([]byte{kind}, pub...)))
}

func TestCosignedNote(t *testing.T) {
	logKey := ed25519.NewKeyFromSeed(make([]byte, 32))
	logPub := logKey.Public().(ed25519.PublicKey)
	seed := make([]byte, 32)
	seed[0] = 1
	wKey := ed25519.NewKeyFromSeed(seed)
	wPub := wKey.Public().(ed25519.PublicKey)
	root := treeRoot([][32]byte{leafHash([]byte("a")), leafHash([]byte("b"))})
	origin := "example.org/log"
	body := fmt.Sprintf("%s\n2\n%s\n", origin, base64.StdEncoding.EncodeToString(root[:]))
	logSig := append(noteKeyID(origin, 0x01, logPub), ed25519.Sign(logKey, []byte(body))...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, 1000)
	msg := "cosignature/v1\ntime 1000\n" + body
	co := append(append(noteKeyID("w.example", 0x04, wPub), ts...), ed25519.Sign(wKey, []byte(msg))...)
	note := body + "\n— " + origin + " " + base64.StdEncoding.EncodeToString(logSig) +
		"\n— w.example " + base64.StdEncoding.EncodeToString(co) + "\n"
	cos := []any{vkeyFor("w.example", 0x04, wPub)}
	got := verifyCosigned([]byte(note), origin, hex.EncodeToString(logPub), cos, 1, 2, root, 2000)
	if len(got) != 1 || got[0]["name"] != "w.example" {
		t.Fatal("cosigner not found")
	}
	cases := map[string]func(){
		"wrong size": func() { verifyCosigned([]byte(note), origin, hex.EncodeToString(logPub), cos, 1, 3, root, 2000) },
		"wrong root": func() {
			verifyCosigned([]byte(note), origin, hex.EncodeToString(logPub), cos, 1, 2, leafHash(nil), 2000)
		},
		"wrong origin": func() {
			verifyCosigned([]byte(note), "other.org/log", hex.EncodeToString(logPub), cos, 1, 2, root, 2000)
		},
		"wrong log key":  func() { verifyCosigned([]byte(note), origin, hex.EncodeToString(wPub), cos, 1, 2, root, 2000) },
		"quorum not met": func() { verifyCosigned([]byte(note), origin, hex.EncodeToString(logPub), cos, 2, 2, root, 2000) },
		"future cosign":  func() { verifyCosigned([]byte(note), origin, hex.EncodeToString(logPub), cos, 1, 2, root, 500) },
		"unknown cosigner": func() {
			verifyCosigned([]byte(note), origin, hex.EncodeToString(logPub), []any{vkeyFor("x.example", 0x04, wPub)}, 1, 2, root, 2000)
		},
		"tampered body": func() {
			verifyCosigned([]byte(strings.Replace(note, "\n2\n", "\n2\nextra\n", 1)), origin, hex.EncodeToString(logPub), cos, 1, 2, root, 2000)
		},
		"one key under two names": func() {
			// The cosignature does not commit to the name, so a copy of the real line
			// under a second name would verify too; the list itself must be refused.
			copied := note + "\u2014 w2.example " + base64.StdEncoding.EncodeToString(append(noteKeyID("w2.example", 0x04, wPub), co[4:]...)) + "\n"
			verifyCosigned([]byte(copied), origin, hex.EncodeToString(logPub), append(cos, vkeyFor("w2.example", 0x04, wPub)), 2, 2, root, 2000)
		},
		"small-order cosigner key": func() {
			// With the identity point as key, R = identity and S = 0 verifies on any
			// message, so anyone could forge this cosignature.
			id := make([]byte, 32)
			id[0] = 1
			forged := make([]byte, 64)
			forged[0] = 1
			sig := append(append(noteKeyID("x.example", 0x04, id), ts...), forged...)
			withForgery := note + "\u2014 x.example " + base64.StdEncoding.EncodeToString(sig) + "\n"
			verifyCosigned([]byte(withForgery), origin, hex.EncodeToString(logPub), []any{vkeyFor("x.example", 0x04, id)}, 1, 2, root, 2000)
		},
		"carriage return": func() {
			verifyCosigned([]byte(strings.ReplaceAll(note, "\n", "\r\n")), origin, hex.EncodeToString(logPub), cos, 1, 2, root, 2000)
		},
		"cosignature origin": func() {
			verifyCosigned([]byte(note), "cosignature/v1", hex.EncodeToString(logPub), cos, 1, 2, root, 2000)
		},
		"duplicate cosigner": func() {
			verifyCosigned([]byte(note), origin, hex.EncodeToString(logPub), append(cos, cos[0]), 1, 2, root, 2000)
		},
	}
	for name, f := range cases {
		if !fails(f) {
			t.Errorf("%s: accepted", name)
		}
	}
}
