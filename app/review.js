// The review page: the owner sees one proposal and approves exactly it.
//
// This page is trusted for what the owner sees (docs/TCB.md). It keeps its own
// copy of the proposal it shows, checks the approval the gate signs against
// that copy, and computes the passkey challenge from it (approval.js). It runs
// as its own document: no dashboard code is loaded here.
import {
  $,
  el,
  say,
  api,
  startSession,
  linkWorkspace,
  fromBase64url,
  toBase64url,
  busy,
} from "./common.js";
import { checkedDigest, hex, sha256Text } from "./approval.js";

const id = location.hash.slice(1);
let shown = null; // The proposal exactly as this page shows it.
let token = "";
let workspace = "";

// Line diff by longest common subsequence. Display only: the approval binds
// the proposal text, never this rendering.
function lineDiff(before, after) {
  const a = before.split("\n"),
    b = after.split("\n");
  const n = a.length,
    m = b.length;
  if (n * m > 4_000_000) return null;
  const w = m + 1,
    t = new Uint32Array((n + 1) * w);
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      t[i * w + j] =
        a[i] === b[j]
          ? t[(i + 1) * w + j + 1] + 1
          : Math.max(t[(i + 1) * w + j], t[i * w + j + 1]);
  const out = [];
  let i = 0,
    j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push(["same", a[i]]);
      i++;
      j++;
    } else if (t[(i + 1) * w + j] >= t[i * w + j + 1]) out.push(["del", a[i++]]);
    else out.push(["add", b[j++]]);
  }
  while (i < n) out.push(["del", a[i++]]);
  while (j < m) out.push(["add", b[j++]]);
  return out;
}

function renderDiff(current) {
  const proposed = shown.content;
  // The current text comes from the owner app and is not checked here.
  const lines = [
    el(
      "div",
      "Compared with the current text as the owner app reports it. You approve the full new text.",
      "diff-note",
    ),
  ];
  let ops;
  if (!current) {
    lines.push(
      el(
        "div",
        "The receiver did not return the current text, so changes cannot be shown. Review the full new text.",
        "diff-note",
      ),
    );
    ops = proposed.split("\n").map((l) => ["same", l]);
    $("review-delta").textContent = "Current text unavailable";
  } else if (current.content === null) {
    lines.push(el("div", "New document. Every line is added.", "diff-note"));
    ops = proposed.split("\n").map((l) => ["add", l]);
    $("review-delta").textContent = "New document";
  } else {
    ops = lineDiff(String(current.content), proposed);
    if (!ops) {
      lines.push(
        el("div", "Too large to compare line by line. Review the full new text.", "diff-note"),
      );
      ops = proposed.split("\n").map((l) => ["same", l]);
      $("review-delta").textContent = "Large change";
    } else {
      const add = ops.filter((o) => o[0] === "add").length,
        del = ops.filter((o) => o[0] === "del").length;
      $("review-delta").textContent =
        add || del ? "+" + add + " / −" + del + " lines" : "No text change";
      if (current.version !== shown.expected_version)
        lines.push(
          el(
            "div",
            "The receiver is now at version " +
              current.version +
              ", not " +
              shown.expected_version +
              ". The receiver will refuse this change.",
            "diff-note",
          ),
        );
    }
  }
  for (const [op, line] of ops) {
    const row = el("div", null, "diff-line");
    row.dataset.op = op;
    row.append(el("span", op === "add" ? "+" : op === "del" ? "−" : ""), el("span", line || " "));
    lines.push(row);
  }
  $("review-diff").replaceChildren(...lines);
}

function showTab(which) {
  const diff = which === "diff";
  $("tab-diff").setAttribute("aria-selected", String(diff));
  $("tab-full").setAttribute("aria-selected", String(!diff));
  $("review-diff").hidden = !diff;
  $("review-content").hidden = diff;
}

async function passkeyAssertion(challenge, result) {
  const publicKey = {
    challenge,
    rpId: result.rp_id,
    userVerification: "required",
    timeout: 120000,
  };
  if (result.credential_id)
    publicKey.allowCredentials = [
      { type: "public-key", id: fromBase64url(result.credential_id) },
    ];
  const credential = await navigator.credentials.get({ publicKey });
  const response = credential.response;
  return {
    authenticator_data: toBase64url(response.authenticatorData),
    client_data_json: toBase64url(response.clientDataJSON),
    signature: toBase64url(response.signature),
  };
}

async function approve() {
  if (!shown || !$("confirm").checked) return;
  $("confirm").disabled = true;
  const result = await api("approve", { id, review_token: token });
  token = "";
  if (result.status === "passkey_required") {
    // Check the signed approval against this page's copy and derive the
    // challenge from it. A mismatch stops here, before any passkey prompt.
    const digest = await checkedDigest(result.approval, shown, result.approval_sha256);
    $("review-approval").textContent = hex(digest);
    $("review-approval").hidden = false;
    $("passkey-note").hidden = false;
    say("Confirm with your passkey to approve this exact change.");
    let assertion;
    try {
      assertion = await passkeyAssertion(digest, result);
    } catch {
      throw Error(
        "Passkey approval was not completed. Nothing was approved. Review the change again.",
      );
    }
    await api("approve/passkey", {
      id,
      assertion_token: result.assertion_token,
      assertion,
    });
  } else if (result.status !== "approved") {
    throw Error("The approval was not stored. Review the change again.");
  }
  location.assign(workspace + "/#approved");
}

async function start() {
  if (!/^[0-9a-f]{64}$/.test(id)) throw Error("No proposal to review.");
  workspace = (await startSession()).workspace;
  linkWorkspace(workspace);
  const r = await api("review", { id });
  const p = r.proposal;
  if (
    !p ||
    typeof p.document !== "string" ||
    typeof p.content !== "string" ||
    !Number.isSafeInteger(p.expected_version)
  )
    throw Error("The proposal could not be read.");
  // Freeze this page's copy: what is rendered is what the approval is checked against.
  shown = Object.freeze({
    document: p.document,
    expected_version: p.expected_version,
    content: p.content,
  });
  token = r.review_token;
  $("review-doc").textContent = shown.document;
  $("review-target").textContent =
    "v" + shown.expected_version + " → v" + (shown.expected_version + 1);
  $("review-content").textContent = shown.content;
  $("review-digest").textContent = await sha256Text(shown.content);
  renderDiff(r.current);
  // The full new text is what the approval binds, so it is shown first.
  showTab("full");
  $("loading").hidden = true;
  $("review").hidden = false;
  $("confirm").focus();
}

$("tab-diff").onclick = () => showTab("diff");
$("tab-full").onclick = () => showTab("full");
$("confirm").onchange = () => {
  $("approve").disabled = !$("confirm").checked;
};
$("approve").onclick = async () => {
  const ok = await busy($("approve"), approve);
  if (!ok) {
    // The review token is used up. A new review starts from fresh state.
    $("again-link").href = "/review#" + id;
    $("again-link").onclick = (e) => {
      e.preventDefault();
      location.reload();
    };
    $("again").hidden = false;
  }
};

start().catch((e) => {
  $("loading").textContent = e.message;
  say(e.message, "bad");
});
