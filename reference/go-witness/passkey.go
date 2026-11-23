package main

// Passkey owner approvals: the same rule as crates/openproof-witness/src/passkey.rs,
// implemented separately with the Go standard library.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxAuthenticatorData = 1024
const maxClientDataJSON = 2048
const maxAssertionSignature = 80

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var digits = regexp.MustCompile(`^[0-9]+$`)

func dnsName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if digits.MatchString(labels[len(labels)-1]) {
		return false
	}
	for _, l := range labels {
		if !dnsLabel.MatchString(l) {
			return false
		}
	}
	return true
}

func validPort(s string) bool {
	if s == "" || len(s) > 5 || s[0] == '0' || !digits.MatchString(s) {
		return false
	}
	p, e := strconv.Atoi(s)
	return e == nil && p >= 1 && p <= 65535
}

// originHost accepts exactly http://localhost:PORT or https://HOST[:PORT].
func originHost(origin string) string {
	if rest, ok := strings.CutPrefix(origin, "http://"); ok {
		host, port, found := strings.Cut(rest, ":")
		need(found && host == "localhost" && validPort(port))
		return host
	}
	rest, ok := strings.CutPrefix(origin, "https://")
	need(ok)
	host, port, found := strings.Cut(rest, ":")
	need(dnsName(host) && (!found || validPort(port)))
	return host
}

func passkeyPoint(v any) *ecdsa.PublicKey {
	raw := hexbytes(v, 65)
	need(raw[0] == 4)
	_, e := ecdh.P256().NewPublicKey(raw)
	need(e == nil)
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:])
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

func ownerPasskey(v any) map[string]any {
	k := obj(v)
	fields(k, "public_key", "rp_id", "origin", "from_sequence")
	passkeyPoint(k["public_key"])
	rp := str(k["rp_id"])
	need(dnsName(rp))
	host := originHost(str(k["origin"]))
	need(host == rp || strings.HasSuffix(host, "."+rp))
	n := num(k["from_sequence"])
	need(n > 0 && n <= uint64(1<<63-1))
	return k
}

// request checks the request envelope; owner_assertion is optional.
func request(v any) map[string]any {
	q := obj(v)
	if a, ok := q["owner_assertion"]; ok {
		fields(q, "approval", "content", "owner_assertion")
		fields(obj(a), "authenticator_data", "client_data_json", "signature")
	} else {
		fields(q, "approval", "content")
	}
	return q
}

func unpadded(v any, max int) []byte {
	b, e := base64.RawURLEncoding.Strict().DecodeString(str(v))
	need(e == nil && len(b) > 0 && len(b) <= max)
	return b
}

// clientData parses a top-level JSON object and rejects duplicate keys.
func clientData(raw []byte) map[string]json.RawMessage {
	need(utf8.Valid(raw))
	quotedUnicode(raw)
	d := json.NewDecoder(bytes.NewReader(raw))
	start, e := d.Token()
	need(e == nil && start == json.Delim('{'))
	m := map[string]json.RawMessage{}
	for d.More() {
		k, e := d.Token()
		need(e == nil)
		s := str(k)
		_, exists := m[s]
		need(!exists)
		var v json.RawMessage
		need(d.Decode(&v) == nil)
		m[s] = v
	}
	end, e := d.Token()
	need(e == nil && end == json.Delim('}'))
	_, e = d.Token()
	need(e == io.EOF)
	return m
}

func jsonText(m map[string]json.RawMessage, key string) string {
	raw, ok := m[key]
	need(ok && len(raw) > 0 && raw[0] == '"')
	var s string
	need(json.Unmarshal(raw, &s) == nil)
	return s
}

func verifyAssertion(a map[string]any, k map[string]any, approvalDigest string) {
	fields(a, "authenticator_data", "client_data_json", "signature")
	auth := unpadded(a["authenticator_data"], maxAuthenticatorData)
	client := unpadded(a["client_data_json"], maxClientDataJSON)
	der := unpadded(a["signature"], maxAssertionSignature)
	digest, e := hex.DecodeString(approvalDigest)
	need(e == nil && len(digest) == 32)
	m := clientData(client)
	need(jsonText(m, "type") == "webauthn.get")
	need(jsonText(m, "challenge") == base64.RawURLEncoding.EncodeToString(digest))
	need(jsonText(m, "origin") == str(k["origin"]))
	if raw, ok := m["crossOrigin"]; ok {
		need(bytes.Equal(bytes.TrimSpace(raw), []byte("false")))
	}
	need(len(auth) >= 37)
	rp := sha256.Sum256([]byte(str(k["rp_id"])))
	need(bytes.Equal(auth[:32], rp[:]))
	need(auth[32]&0x01 != 0 && auth[32]&0x04 != 0)
	clientHash := sha256.Sum256(client)
	signed := sha256.Sum256(append(append([]byte{}, auth...), clientHash[:]...))
	need(ecdsa.VerifyASN1(passkeyPoint(k["public_key"]), signed[:], der))
}

// ownerPasskeys: every owner passkey of a trust, oldest first: the retired ones,
// then the current one.
func ownerPasskeys(t map[string]any) []any {
	var all []any
	if r, ok := t["retired_owner_passkeys"]; ok {
		all = append(all, arr(r)...)
	}
	if k, ok := t["owner_passkey"]; ok {
		all = append(all, k)
	}
	return all
}

// ownerAssertion: an assertion is required exactly when a passkey of the trust
// was in force at the receipt sequence: the one with the latest from_sequence at
// or before it. Otherwise it must be absent.
func ownerAssertion(q map[string]any, t map[string]any, approvalDigest string, sequence uint64) {
	a, present := q["owner_assertion"]
	var k any
	for _, p := range ownerPasskeys(t) {
		if sequence >= num(obj(p)["from_sequence"]) {
			k = p
		}
	}
	need((k != nil) == present)
	if k != nil {
		verifyAssertion(obj(a), obj(k), approvalDigest)
	}
}

// replacementReceipt: every owner passkey after the first one starts right after
// a receiver receipt of kind "passkey" that carries its hash. True when r is that
// receipt. A "passkey" receipt that the trust does not explain is refused, and so
// is a replacement without its receipt.
func replacementReceipt(t, r map[string]any) bool {
	var starts any
	for i, p := range ownerPasskeys(t) {
		if i > 0 && num(obj(p)["from_sequence"]) == num(r["sequence"])+1 {
			starts = p
		}
	}
	replaced := str(r["kind"]) == "passkey"
	need((starts != nil) == replaced)
	if replaced {
		need(str(r["document"]) == "" && num(r["document_version"]) == 0 && str(r["reason"]) == "" && str(r["approval_sha256"]) == zero && str(r["content_sha256"]) == hash(string(canonical(starts))))
	}
	return replaced
}

// samePasskey: once a trust in a history has owner passkeys, a later trust keeps
// them as they are. It can add a passkey only when the receipt before its start is
// still to come, so that this receipt is checked under the later trust.
func samePasskey(old, next map[string]any, count uint64) {
	a, b := ownerPasskeys(old), ownerPasskeys(next)
	need(len(b) >= len(a))
	for i, k := range b {
		if i < len(a) {
			need(bytes.Equal(canonical(a[i]), canonical(k)))
		} else if i > 0 {
			need(num(obj(k)["from_sequence"]) > count+1)
		}
	}
}
