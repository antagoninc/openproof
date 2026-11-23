// Shared by the owner pages: the session, requests to the owner app, and
// text-only rendering. Every value from the server is set as text, never HTML.

let csrf = "";
let toastTimer = 0;

export const $ = (id) => document.getElementById(id);

export function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

export function say(text, tone) {
  const t = $("message");
  t.textContent = text;
  t.dataset.tone = tone || "";
  t.classList.remove("quiet");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(
    () => t.classList.add("quiet"),
    tone === "bad" ? 12000 : 7000,
  );
}

export async function api(path, body) {
  const options = { credentials: "same-origin", cache: "no-store" };
  if (body !== undefined) {
    options.method = "POST";
    options.headers = {
      "Content-Type": "application/json",
      "X-OpenProof-CSRF": csrf,
    };
    options.body = JSON.stringify(body);
  }
  const response = await fetch("/api/" + path, options);
  const data = await response.json();
  if (!response.ok) throw Error(data.error || "Operation unavailable");
  return data;
}

/**
 * Start the owner session: with the launcher's token, or with the cookie.
 * Returns the two origins: `review` (the passkey's) and `workspace`.
 */
export async function startSession(token) {
  let s;
  try {
    s = token ? await api("session", { token }) : await api("session");
  } catch {
    throw Error(
      "No owner session. Open the app with the link the launcher printed.",
    );
  }
  csrf = s.csrf;
  return s;
}

/** Point the page's workspace links at the workspace origin. */
export function linkWorkspace(origin) {
  for (const a of document.querySelectorAll("a[data-workspace]")) a.href = origin + "/";
}

export function fromBase64url(text) {
  const s = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(s + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function toBase64url(buffer) {
  let binary = "";
  for (const b of new Uint8Array(buffer)) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * The code of a passkey, as the administrator's tool computes it
 * (scripts/roles_passkey.py): the first 20 hexadecimal characters of the
 * SHA-256 of the 65-byte P-256 point in hexadecimal, the relying party and
 * the origin, one on each line, in groups of four. `publicKey` is the key as
 * the authenticator returned it to the page, in base64url; the point is its
 * last 65 bytes. The page gives its own host name and origin.
 */
export async function passkeyCode(publicKey, rpId, origin) {
  const der = fromBase64url(publicKey);
  const point = der.slice(-65);
  if (der.length !== 91 || point[0] !== 4) throw Error("The passkey must use ES256 (P-256).");
  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const text = new TextEncoder().encode([hex(point), rpId, origin].join("\n"));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", text));
  return hex(digest.slice(0, 10)).toUpperCase().match(/.{4}/g).join("-");
}

/** Mark a button busy while `fn` runs; show a failure as a message. */
export async function busy(button, fn) {
  button.disabled = true;
  button.classList.add("busy");
  button.setAttribute("aria-busy", "true");
  try {
    await fn();
  } catch (e) {
    say(e.message, "bad");
    return false;
  } finally {
    button.classList.remove("busy");
    button.removeAttribute("aria-busy");
  }
  return true;
}
