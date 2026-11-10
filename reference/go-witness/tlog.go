package main

// Checks that a C2SP checkpoint, signed by the log (the OpenProof witness) and
// cosigned by independent witnesses, commits to exactly the verified history.
// Written from c2sp.org/tlog-checkpoint, c2sp.org/signed-note and
// c2sp.org/tlog-cosignature (Ed25519 cosignatures, type 0x04), and RFC 6962.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func leafHash(data []byte) [32]byte {
	return sha256.Sum256(append([]byte{0}, data...))
}

func nodeHash(l, r [32]byte) [32]byte {
	b := append([]byte{1}, l[:]...)
	return sha256.Sum256(append(b, r[:]...))
}

// treeRoot is RFC 6962 MTH over already-hashed leaves.
func treeRoot(leaves [][32]byte) [32]byte {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return leaves[0]
	}
	k := 1
	for k<<1 < len(leaves) {
		k <<= 1
	}
	return nodeHash(treeRoot(leaves[:k]), treeRoot(leaves[k:]))
}

func noteKeyID(name string, kind byte, key []byte) []byte {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', kind})
	h.Write(key)
	return h.Sum(nil)[:4]
}

// parseVkey parses name+hexid+base64(type||key) and checks the key ID.
func parseVkey(v string, kind byte) (string, []byte) {
	parts := strings.SplitN(v, "+", 3)
	need(len(parts) == 3 && parts[0] != "")
	raw := strictB64(parts[2])
	need(len(raw) == 33 && raw[0] == kind)
	need(hex.EncodeToString(noteKeyID(parts[0], kind, raw[1:])) == parts[1])
	// Refuse small-order keys: with one, a fixed signature verifies on any note.
	point(raw[1:])
	return parts[0], raw[1:]
}

// strictB64 decodes canonical standard base64 only (c2sp.org/signed-note:
// "decoders MUST reject non-canonical encodings").
func strictB64(s string) []byte {
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	need(err == nil && base64.StdEncoding.EncodeToString(raw) == s)
	return raw
}

// validOrigin matches the Rust rule: printable ASCII without spaces, and never an
// OpenProof signing domain or a cosignature header.
func validOrigin(o string) bool {
	for _, c := range []byte(o) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("./_-:", c) >= 0) {
			return false
		}
	}
	return o != "" && len(o) <= 255 && !strings.HasPrefix(o, "OpenProof") && !strings.HasPrefix(o, "cosignature/")
}

type sigLine struct {
	name string
	raw  []byte
}

// verifyCosigned checks the note against the history (size, root), the log's own
// signature under the trust's witness key, and a quorum of listed cosigners.
func verifyCosigned(note []byte, origin, witnessHex string, cosigners []any, quorum int, size uint64, root [32]byte, now uint64) []map[string]any {
	text := string(note)
	need(validOrigin(origin) && len(text) <= 1<<16 && strings.HasSuffix(text, "\n"))
	for _, c := range text {
		need(c == '\n' || (c >= 0x20 && c != 0x7f && !(c >= 0x80 && c < 0xa0)))
	}
	// The signatures follow the last empty line (c2sp.org/signed-note).
	split := strings.LastIndex(text, "\n\n")
	need(split >= 0)
	body, sigs := text[:split]+"\n", text[split+2:]
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	need(len(lines) >= 3 && lines[0] == origin)
	need(lines[1] == strconv.FormatUint(size, 10))
	need(lines[2] == base64.StdEncoding.EncodeToString(root[:]))
	var signatures []sigLine
	for _, l := range strings.Split(strings.TrimSuffix(sigs, "\n"), "\n") {
		rest, ok := strings.CutPrefix(l, "— ")
		need(ok)
		name, b64, ok := strings.Cut(rest, " ")
		need(ok)
		raw := strictB64(b64)
		need(len(raw) >= 4)
		signatures = append(signatures, sigLine{name, raw})
	}
	witness := key(witnessHex)
	logID := noteKeyID(origin, 0x01, witness)
	logSigned := false
	for _, s := range signatures {
		if s.name == origin && len(s.raw) == 68 && bytes.Equal(s.raw[:4], logID) &&
			ed25519.Verify(witness, []byte(body), s.raw[4:]) {
			logSigned = true
		}
	}
	need(logSigned)
	var out []map[string]any
	// A cosignature does not commit to the cosigner's name, so one key must
	// never count twice (c2sp.org/tlog-cosignature).
	seen := map[string]bool{}
	for _, v := range cosigners {
		name, key := parseVkey(str(v), 0x04)
		need(!seen["name:"+name] && !seen["key:"+string(key)])
		seen["name:"+name], seen["key:"+string(key)] = true, true
		id := noteKeyID(name, 0x04, key)
		for _, s := range signatures {
			if s.name != name || len(s.raw) != 76 || !bytes.Equal(s.raw[:4], id) {
				continue
			}
			ts := binary.BigEndian.Uint64(s.raw[4:12])
			msg := fmt.Sprintf("cosignature/v1\ntime %d\n%s", ts, body)
			if ts <= now+300 && ed25519.Verify(key, []byte(msg), s.raw[12:]) {
				out = append(out, map[string]any{"name": name, "time": ts})
				break
			}
		}
	}
	need(quorum >= 1 && len(out) >= quorum)
	return out
}
