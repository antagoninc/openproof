// The approval the owner's passkey signs, checked in the page itself.
//
// The receiver admits a change only with a passkey assertion whose challenge
// is the digest of the exact approval (docs/PASSKEY.md). This module computes
// that digest here, from an approval the page has first compared with what it
// shows. The server never chooses the challenge, so a defect on the server
// side cannot make the owner's passkey sign content the page did not show.
//
// The digest is SHA-256 of "OpenProof/v1/document-approval/1\0" followed by
// the OPEC-1 encoding of the approval (crates/openproof-core canonical()).

const DOMAIN = "OpenProof/v1/document-approval/1\0";
const VERSION = "openproof-witness/1";
const MAX_WINDOW = 600;
// Clock difference allowed between this page and the gate, on one computer.
const SKEW = 60;
// The Approval fields, in OPEC-1 key order (bytewise; all ASCII).
const FIELDS = [
  "authority",
  "content_sha256",
  "document",
  "expected_version",
  "expires_at",
  "nonce",
  "not_before",
  "receiver",
  "version",
];
const INTEGERS = new Set(["expected_version", "expires_at", "not_before"]);
const HEX64 = /^[0-9a-f]{64}$/;

function u64(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}
function text(s) {
  const bytes = new TextEncoder().encode(s);
  return [Uint8Array.of(4), u64(bytes.length), bytes];
}
function join(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

export async function sha256Text(s) {
  return hex(await sha256(new TextEncoder().encode(s)));
}

/** The approval's structure: exactly these fields, with these types. */
function shape(a) {
  if (a === null || typeof a !== "object" || Array.isArray(a))
    throw Error("The approval is missing.");
  const keys = Object.keys(a).sort();
  if (keys.length !== FIELDS.length || keys.some((k, i) => k !== FIELDS[i]))
    throw Error("The approval has unexpected fields.");
  for (const k of FIELDS) {
    const v = a[k];
    const ok = INTEGERS.has(k)
      ? Number.isSafeInteger(v) && v >= 0
      : typeof v === "string";
    if (!ok) throw Error("The approval field " + k + " is malformed.");
  }
}

/** The bytes the passkey signs over, as the receiver computes them. */
export function signingBytes(a) {
  shape(a);
  const parts = [
    new TextEncoder().encode(DOMAIN),
    new TextEncoder().encode("OPEC\x01"),
    Uint8Array.of(6),
    u64(FIELDS.length),
  ];
  for (const k of FIELDS) {
    parts.push(...text(k));
    if (INTEGERS.has(k)) parts.push(Uint8Array.of(3), u64(a[k]));
    else parts.push(...text(a[k]));
  }
  return join(parts);
}

/**
 * Check that `a` approves exactly what the page shows, now, then return the
 * digest that becomes the passkey challenge. `shown` is the page's own copy of
 * the document name, expected version and content. `now` is Unix seconds.
 * Throws on any difference.
 */
export async function checkedDigest(
  a,
  shown,
  serverDigest,
  now = Math.floor(Date.now() / 1000),
) {
  shape(a);
  const problems = [];
  if (a.version !== VERSION) problems.push("approval version");
  if (a.document !== shown.document) problems.push("document");
  if (a.expected_version !== shown.expected_version) problems.push("version");
  if (a.content_sha256 !== (await sha256Text(shown.content)))
    problems.push("content");
  for (const k of ["authority", "receiver", "nonce", "content_sha256"])
    if (!HEX64.test(a[k])) problems.push(k);
  if (a.not_before > a.expires_at || a.expires_at - a.not_before > MAX_WINDOW)
    problems.push("validity window");
  // Valid from now: never an approval that starts later or has already ended.
  if (a.not_before > now + SKEW || a.expires_at < now) problems.push("validity time");
  const digest = await sha256(signingBytes(a));
  if (serverDigest !== hex(digest)) problems.push("digest");
  if (problems.length)
    throw Error(
      "The approval does not match the change shown here (" +
        problems.join(", ") +
        "). Nothing was approved.",
    );
  return digest;
}
