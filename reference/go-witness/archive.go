package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
)

type chain struct {
	Count   uint64
	Head    string
	Last    uint64
	Gaps    bool
	Nonces  map[string]bool
	Docs    map[string]uint64
	Issuers map[string]bool
	// Leaves is the RFC 6962 leaf hash of each receipt digest, in sequence
	// order, for checking a cosigned transparency-log checkpoint.
	Leaves    [][32]byte
	Handovers int
}

func pageStep(t map[string]any, pinv, pv any, now uint64, c *chain) bool {
	p := obj(pv)
	fields(p, "version", "start", "requests", "receipts", "checkpoint")
	need(str(p["version"]) == "openproof-history-page/1" && num(p["start"]) == c.Count+1)
	cp := checkpoint(pinv, t, now)
	need(bytes.Equal(canonical(pinv), canonical(p["checkpoint"])))
	need(num(cp["count"]) <= 100000 && now-num(cp["observed_at"]) <= 300 && c.Count <= num(cp["count"]))
	rs, qs := arr(p["receipts"]), arr(p["requests"])
	need(len(rs) <= 32 && len(qs) <= 32)
	var compact bytes.Buffer
	encoder := json.NewEncoder(&compact)
	encoder.SetEscapeHTML(false)
	need(encoder.Encode(p) == nil)
	need(compact.Len()-1 <= 512*1024)
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
	head := c.Head
	last := c.Last
	gaps := c.Gaps
	used := c.Nonces
	versions := c.Docs
	for _, v := range rs {
		r := signed(v, t["receiver"], "receiver-receipt/1")
		fields(r, "version", "kind", "sequence", "previous", "approval_sha256", "document", "document_version", "content_sha256", "observed_at", "reason")
		need(str(r["version"]) == version)
		for _, n := range []string{"previous", "approval_sha256", "content_sha256"} {
			hexbytes(r[n], 32)
		}
		at := num(r["observed_at"])
		need(num(r["sequence"]) == c.Count+1 && str(r["previous"]) == head && at >= last && at <= num(cp["observed_at"]))
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
			delete(requests, str(r["approval_sha256"]))
			need(ok)
			a := approval(obj(q["approval"])["payload"])
			issuer := str(a["authority"])
			c.Issuers[issuer] = true
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
		c.Leaves = append(c.Leaves, leafHash(hexbytes(head, 32)))
		c.Count++
	}

	need(len(requests) == 0 && c.Count <= num(cp["count"]))
	c.Head = head
	c.Last = last
	c.Gaps = gaps
	complete := c.Count == num(cp["count"])
	if complete {
		need(head == str(cp["head"]))
	}
	return complete
}
func rootTrust(v any, root string, at uint64) map[string]any {
	t := trust(signed(v, root, "witness-trust/1"), at)
	need(root != str(t["authority"]) && root != str(t["receiver"]) && root != str(t["witness"]) && !contains(t["previous_authorities"], root) && !contains(t["revoked_authorities"], root))
	return t
}
func rotationStep(hv, oldv any, root string, confirmed any, c *chain) (string, map[string]any) {
	h := obj(hv)
	roles := []string{"old_root", "new_root", "old_receiver", "new_receiver", "old_witness", "new_witness"}
	fields(h, roles...)
	r := obj(obj(h["old_root"])["payload"])
	fields(r, "version", "old_root", "new_root", "old_trust_sha256", "new_trust", "checkpoint", "not_before", "expires_at")
	need(str(r["version"]) == "openproof-rotation/1" && str(r["old_root"]) == root)
	at, end := num(r["not_before"]), num(r["expires_at"])
	need(end >= at && end-at <= 600)
	old := rootTrust(oldv, root, at)
	nt := trust(r["new_trust"], at)
	need(num(nt["epoch"]) > num(old["epoch"]))
	samePasskey(old, nt)
	sum := sha256.Sum256(canonical(old))
	need(str(r["old_trust_sha256"]) == hex.EncodeToString(sum[:]))
	nr := str(r["new_root"])
	key(nr)
	need(nr != str(nt["authority"]) && nr != str(nt["receiver"]) && nr != str(nt["witness"]) && !contains(nt["previous_authorities"], nr) && !contains(nt["revoked_authorities"], nr))
	keys := []any{root, nr, old["receiver"], nt["receiver"], old["witness"], nt["witness"]}
	for i, role := range roles {
		p := signed(h[role], keys[i], "witness-planned-rotation/1")
		need(bytes.Equal(canonical(p), canonical(r)))
	}
	cp := checkpoint(r["checkpoint"], old, at)
	need(at-num(cp["observed_at"]) <= 300)
	need(confirmed != nil && bytes.Equal(canonical(confirmed), canonical(r["checkpoint"])) && num(cp["count"]) == c.Count && str(cp["head"]) == c.Head)
	return nr, nt
}

// cosign is the optional cosigned-checkpoint check: the note, its origin, the
// trusted cosigner vkeys and how many of them must have cosigned.
type cosign struct {
	Note      []byte
	Origin    string
	Cosigners []any
	Quorum    int
}

func verifyArchive(root string, pin any, directory string, now uint64) map[string]any {
	return verifyArchiveCosigned(root, pin, directory, now, nil)
}

func verifyArchiveCosigned(root string, pin any, directory string, now uint64, co *cosign) map[string]any {
	key(root)
	m := obj(read(filepath.Join(directory, "manifest.json")))
	fields(m, "version", "entries")
	need(str(m["version"]) == "openproof-portable-history/1")
	entries := arr(m["entries"])
	need(len(entries) > 0 && len(entries) <= 4096)
	c := chain{Head: zero, Nonces: map[string]bool{}, Docs: map[string]uint64{}, Issuers: map[string]bool{}}
	var current map[string]any
	var confirmed any
	var finalSigned any
	total := 0
	observedFloor := uint64(0)
	seen := map[string]bool{}
	for _, entry := range entries {
		e := obj(entry)
		fields(e, "file", "sha256")
		name := str(e["file"])
		need(regexp.MustCompile(`^entry-[0-9]{6}\.json$`).MatchString(name) && !seen[name])
		seen[name] = true
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		need(err == nil && info.Mode().IsRegular() && info.Size() <= 1048576)
		raw, err := os.ReadFile(path)
		need(err == nil)
		total += len(raw)
		need(total <= 256*1024*1024)
		sum := sha256.Sum256(raw)
		need(str(e["sha256"]) == hex.EncodeToString(sum[:]))
		step := obj(parse(raw))
		kind := str(step["kind"])
		if kind == "page" {
			fields(step, "kind", "signed_trust", "page")
			page := obj(step["page"])
			cp := obj(obj(page["checkpoint"])["payload"])
			at := num(cp["observed_at"])
			need(at <= now && at >= observedFloor)
			t := rootTrust(step["signed_trust"], root, at)
			if current != nil {
				need(num(t["epoch"]) >= num(current["epoch"]) && str(t["receiver"]) == str(current["receiver"]) && str(t["witness"]) == str(current["witness"]))
				if num(t["epoch"]) == num(current["epoch"]) {
					need(bytes.Equal(canonical(t), canonical(current)))
				}
				samePasskey(current, t)
			}
			for issuer := range c.Issuers {
				need((issuer == str(t["authority"]) || contains(t["previous_authorities"], issuer)) && !contains(t["revoked_authorities"], issuer))
			}
			if confirmed != nil {
				prior := obj(obj(confirmed)["payload"])
				need(at >= num(prior["observed_at"]))
			}
			if pageStep(t, page["checkpoint"], page, at, &c) {
				confirmed = page["checkpoint"]
				observedFloor = at
			} else {
				confirmed = nil
			}
			current = t
			finalSigned = step["signed_trust"]
		} else {
			need(kind == "handover")
			fields(step, "kind", "old_signed_trust", "handover")
			need(current != nil)
			old := obj(obj(step["old_signed_trust"])["payload"])
			need(bytes.Equal(canonical(old), canonical(current)))
			rotationTime := num(obj(obj(obj(step["handover"])["old_root"])["payload"])["not_before"])
			need(rotationTime <= now && rotationTime >= observedFloor)
			root, current = rotationStep(step["handover"], step["old_signed_trust"], root, confirmed, &c)
			c.Handovers++
			observedFloor = rotationTime
			confirmed = nil
			finalSigned = nil
		}
	}
	need(current != nil && confirmed != nil && finalSigned != nil && bytes.Equal(canonical(pin), canonical(confirmed)))
	rootTrust(finalSigned, root, now)
	cp := checkpoint(pin, current, now)
	need(now-num(cp["observed_at"]) <= 300)
	status := "portable_history_verified"
	if c.Gaps {
		status = "unknown_due_to_disclosed_gap"
	}
	result := map[string]any{"status": status, "complete_history": !c.Gaps, "count": c.Count, "root": root, "verification_scope": "root_authenticated_offline_archive_with_external_checkpoint", "physical_effects_proven": false}
	if co != nil {
		// The cosigned tree must cover exactly this history, under one witness key.
		need(c.Handovers == 0 && uint64(len(c.Leaves)) == c.Count)
		result["cosigned_by"] = verifyCosigned(co.Note, co.Origin, str(current["witness"]), co.Cosigners, co.Quorum, c.Count, treeRoot(c.Leaves), now)
		result["verification_scope"] = "root_authenticated_offline_archive_with_external_checkpoint_and_independent_cosigners"
	}
	return result
}
