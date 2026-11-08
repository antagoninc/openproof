// Separate verifier implementation: no Rust FFI, subprocess or shared protocol code.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"filippo.io/edwards25519"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf8"
)

const version = "openproof-witness/1"
const zero = "0000000000000000000000000000000000000000000000000000000000000000"

func need(b bool) {
	if !b {
		panic("invalid evidence")
	}
}
func obj(v any) map[string]any { m, ok := v.(map[string]any); need(ok); return m }
func str(v any) string         { s, ok := v.(string); need(ok); return s }
func num(v any) uint64 {
	n, ok := v.(json.Number)
	need(ok)
	s := string(n)
	need(regexp.MustCompile(`^(0|[1-9][0-9]*)$`).MatchString(s))
	u, e := strconv.ParseUint(s, 10, 64)
	need(e == nil)
	return u
}
func arr(v any) []any { a, ok := v.([]any); need(ok); return a }
func fields(m map[string]any, names ...string) {
	need(len(m) == len(names))
	for _, n := range names {
		_, ok := m[n]
		need(ok)
	}
}
func hexbytes(v any, n int) []byte {
	s := str(v)
	need(len(s) == n*2 && regexp.MustCompile(`^[0-9a-f]+$`).MatchString(s))
	b, e := hex.DecodeString(s)
	need(e == nil)
	return b
}
func point(b []byte) {
	p, e := new(edwards25519.Point).SetBytes(b)
	need(e == nil)
	need(bytes.Equal(p.Bytes(), b))
	need(new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 0)
}
func key(v any) []byte { b := hexbytes(v, 32); point(b); return b }
func ident(v any)      { need(regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`).MatchString(str(v))) }
func quotedUnicode(raw []byte) { // encoding/json otherwise replaces lone UTF-16 surrogates.
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		i++
		for i < len(raw) && raw[i] != '"' {
			if raw[i] == '\\' {
				i++
				need(i < len(raw))
				if raw[i] == 'u' {
					need(i+4 < len(raw))
					n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
					need(e == nil)
					i += 4
					if n >= 0xd800 && n <= 0xdbff {
						need(i+6 < len(raw) && raw[i+1] == '\\' && raw[i+2] == 'u')
						low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
						need(e == nil && low >= 0xdc00 && low <= 0xdfff)
						i += 6
					} else {
						need(n < 0xdc00 || n > 0xdfff)
					}
				}
			}
			i++
		}
	}
}
func value(d *json.Decoder, depth int) any {
	need(depth <= 64)
	t, e := d.Token()
	need(e == nil)
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				need(e == nil)
				s := str(k)
				_, exists := m[s]
				need(!exists)
				m[s] = value(d, depth+1)
			}
			end, e := d.Token()
			need(e == nil && end == json.Delim('}'))
			return m
		case '[':
			a := []any{}
			for d.More() {
				a = append(a, value(d, depth+1))
			}
			end, e := d.Token()
			need(e == nil && end == json.Delim(']'))
			return a
		default:
			panic("delimiter")
		}
	}
	if _, ok := t.(json.Number); ok {
		num(t)
	}
	return t
}
func parse(b []byte) any {
	need(len(b) <= 1048576 && utf8.Valid(b))
	quotedUnicode(b)
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v := value(d, 0)
	_, e := d.Token()
	need(e == io.EOF)
	return v
}
func read(p string) any {
	f, e := os.Open(p)
	need(e == nil)
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1048577))
	need(e == nil)
	return parse(b)
}
func frame(b *bytes.Buffer, n uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], n)
	b.Write(x[:])
}
func encode(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteByte(0)
	case bool:
		if x {
			b.WriteByte(2)
		} else {
			b.WriteByte(1)
		}
	case json.Number:
		b.WriteByte(3)
		frame(b, num(x))
	case string:
		b.WriteByte(4)
		frame(b, uint64(len(x)))
		b.WriteString(x)
	case []any:
		b.WriteByte(5)
		frame(b, uint64(len(x)))
		for _, e := range x {
			encode(b, e)
		}
	case map[string]any:
		b.WriteByte(6)
		frame(b, uint64(len(x)))
		keys := []string{}
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			encode(b, k)
			encode(b, x[k])
		}
	default:
		panic("type")
	}
	need(b.Len() <= 1048576)
}
func canonical(v any) []byte {
	var b bytes.Buffer
	b.Write([]byte{'O', 'P', 'E', 'C', 1})
	encode(&b, v)
	return b.Bytes()
}
func preimage(domain string, v any) []byte {
	return append([]byte("OpenProof/v1/"+domain+"\x00"), canonical(v)...)
}
func digest(domain string, v any) string {
	h := sha256.Sum256(preimage(domain, v))
	return hex.EncodeToString(h[:])
}
func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func signed(v any, k any, domain string) map[string]any {
	m := obj(v)
	fields(m, "payload", "signature")
	p := obj(m["payload"])
	sig := hexbytes(m["signature"], 64)
	point(sig[:32])
	need(ed25519.Verify(ed25519.PublicKey(key(k)), preimage(domain, p), sig))
	return p
}
func trust(v any, now uint64) map[string]any {
	t := obj(v)
	if k, ok := t["owner_passkey"]; ok {
		fields(t, "version", "epoch", "expires_at", "authority", "receiver", "witness", "previous_authorities", "revoked_authorities", "owner_passkey")
		ownerPasskey(k)
	} else {
		fields(t, "version", "epoch", "expires_at", "authority", "receiver", "witness", "previous_authorities", "revoked_authorities")
	}
	need(str(t["version"]) == version && num(t["epoch"]) > 0 && num(t["epoch"]) <= uint64(1<<63-1) && now <= num(t["expires_at"]))
	a, r, w := str(t["authority"]), str(t["receiver"]), str(t["witness"])
	key(a)
	key(r)
	key(w)
	need(a != r && a != w && r != w)
	for _, n := range []string{"previous_authorities", "revoked_authorities"} {
		list := arr(t[n])
		need(len(list) <= 64)
		seen := map[string]bool{}
		for _, v := range list {
			k := str(v)
			key(k)
			need(!seen[k] && k != a && k != r && k != w)
			seen[k] = true
		}
	}
	return t
}
func contains(a any, s string) bool {
	for _, x := range arr(a) {
		if str(x) == s {
			return true
		}
	}
	return false
}
func approval(v any) map[string]any {
	a := obj(v)
	fields(a, "version", "authority", "document", "expected_version", "content_sha256", "nonce", "receiver", "not_before", "expires_at")
	need(str(a["version"]) == version)
	ident(a["document"])
	key(a["authority"])
	key(a["receiver"])
	hexbytes(a["content_sha256"], 32)
	hexbytes(a["nonce"], 32)
	need(num(a["expected_version"]) < uint64(1<<63-1))
	start, end := num(a["not_before"]), num(a["expires_at"])
	need(start <= end && end-start <= 600)
	return a
}
func checkpoint(v any, t map[string]any, now uint64) map[string]any {
	c := signed(v, t["witness"], "witness-checkpoint/1")
	fields(c, "version", "count", "head", "observed_at", "receiver")
	need(str(c["version"]) == version)
	hexbytes(c["head"], 32)
	key(c["receiver"])
	need(str(c["receiver"]) == str(t["receiver"]) && num(c["observed_at"]) <= now)
	num(c["count"])
	return c
}
func verify(tv, pinv, pv any, now uint64) map[string]any {
	t := trust(tv, now)
	p := obj(pv)
	fields(p, "version", "requests", "receipts", "checkpoint")
	need(str(p["version"]) == version)
	cp := checkpoint(pinv, t, now)
	checkpoint(p["checkpoint"], t, now)
	need(bytes.Equal(canonical(pinv), canonical(p["checkpoint"])))
	rs, qs := arr(p["receipts"]), arr(p["requests"])
	need(len(rs) > 0 && len(rs) <= 4096 && len(qs) <= 4096)
	requests := map[string]map[string]any{}
	for _, v := range qs {
		q := request(v)
		aenv := obj(q["approval"])
		fields(aenv, "payload", "signature")
		a := approval(aenv["payload"])
		h := digest("document-approval/1", a)
		_, exists := requests[h]
		need(!exists)
		requests[h] = q
	}
	head := zero
	last := uint64(0)
	gaps := false
	used := map[string]bool{}
	versions := map[string]uint64{}
	for i, v := range rs {
		r := signed(v, t["receiver"], "receiver-receipt/1")
		fields(r, "version", "kind", "sequence", "previous", "approval_sha256", "document", "document_version", "content_sha256", "observed_at", "reason")
		need(str(r["version"]) == version)
		for _, n := range []string{"previous", "approval_sha256", "content_sha256"} {
			hexbytes(r[n], 32)
		}
		at := num(r["observed_at"])
		need(num(r["sequence"]) == uint64(i+1) && str(r["previous"]) == head && at >= last && at <= num(cp["observed_at"]))
		last = at
		kind := str(r["kind"])
		reason := str(r["reason"])
		need(len(reason) <= 512)
		if kind == "gap" {
			need(str(r["document"]) == "" && num(r["document_version"]) == 0 && reason != "" && str(r["approval_sha256"]) == zero && str(r["content_sha256"]) == zero)
			gaps = true
		} else {
			need(kind == "update" && reason == "" && num(r["document_version"]) > 0)
			ident(r["document"])
			q, ok := requests[str(r["approval_sha256"])]
			need(ok)
			a := approval(obj(q["approval"])["payload"])
			issuer := str(a["authority"])
			need((issuer == str(t["authority"]) || contains(t["previous_authorities"], issuer)) && !contains(t["revoked_authorities"], issuer))
			signed(q["approval"], issuer, "document-approval/1")
			ownerAssertion(q, t, digest("document-approval/1", a), num(r["sequence"]))
			need(str(a["receiver"]) == str(t["receiver"]) && num(a["not_before"]) <= at && at <= num(a["expires_at"]))
			content := str(q["content"])
			need(len(content) > 0 && len(content) <= 8192 && hash(content) == str(a["content_sha256"]))
			nonce := str(a["nonce"])
			need(!used[nonce])
			used[nonce] = true
			doc := str(a["document"])
			expected := num(a["expected_version"])
			need(str(r["document"]) == doc && num(r["document_version"]) == expected+1 && str(r["content_sha256"]) == hash(content))
			if !gaps {
				need(versions[doc] == expected)
			}
			versions[doc] = expected + 1
		}
		head = digest("receiver-receipt/1", r)
	}
	need(num(cp["count"]) == uint64(len(rs)) && str(cp["head"]) == head && len(qs) == len(used))
	status := "receiver_confirmed_and_witnessed"
	if gaps {
		status = "unknown_due_to_disclosed_gap"
	}
	return map[string]any{"status": status, "complete_history": !gaps, "document_version_continuity_verified": !gaps, "verification_scope": "independent_implementation_stateless", "physical_effects_proven": false}
}
func main() {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "verification_failed")
			os.Exit(1)
		}
	}()
	need(len(os.Args) == 6 && (os.Args[1] == "verify" || os.Args[1] == "verify-archive"))
	now, e := strconv.ParseUint(os.Args[5], 10, 64)
	need(e == nil)
	var result map[string]any
	if os.Args[1] == "verify-archive" {
		result = verifyArchive(os.Args[2], read(os.Args[3]), os.Args[4], now)
	} else {
		result = verify(read(os.Args[2]), read(os.Args[3]), read(os.Args[4]), now)
	}
	b, e := json.Marshal(result)
	need(e == nil)
	fmt.Println(string(b))
}
