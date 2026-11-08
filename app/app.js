"use strict";
let csrf = "",
  review = null,
  busy = false;
const $ = (id) => document.getElementById(id),
  say = (text) => {
    $("message").textContent = text;
  };
async function api(path, body) {
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
async function action(fn) {
  if (busy) return;
  busy = true;
  try {
    await fn();
  } catch (e) {
    say(e.message);
  } finally {
    busy = false;
  }
}
function fromBase64url(text) {
  const s = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(s + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}
function toBase64url(buffer) {
  let binary = "";
  for (const b of new Uint8Array(buffer)) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
async function passkeyAssertion(challenge) {
  const publicKey = {
    challenge: fromBase64url(challenge.challenge),
    rpId: challenge.rp_id,
    userVerification: "required",
    timeout: 120000,
  };
  if (challenge.credential_id)
    publicKey.allowCredentials = [
      { type: "public-key", id: fromBase64url(challenge.credential_id) },
    ];
  const credential = await navigator.credentials.get({ publicKey });
  const response = credential.response;
  return {
    authenticator_data: toBase64url(response.authenticatorData),
    client_data_json: toBase64url(response.clientDataJSON),
    signature: toBase64url(response.signature),
  };
}
function showPasskeyChallenge(digest) {
  $("review-approval").textContent = digest;
  $("review-approval").hidden = !digest;
  $("passkey-note").hidden = !digest;
}
function element(tag, text, cls) {
  const e = document.createElement(tag);
  e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
async function refresh() {
  const s = await api("status");
  $("pending").textContent = s.items.filter(
    (x) => x.stage === "Awaiting approval",
  ).length;
  $("committed").textContent = s.items.filter(
    (x) => x.document_version !== undefined,
  ).length;
  $("verified").textContent = s.items.filter(
    (x) => x.stage === "Verified locally",
  ).length;
  $("items").replaceChildren();
  if (!s.items.length)
    $("items").append(
      element(
        "p",
        "No actions yet. Create a proposal below to begin.",
        "empty",
      ),
    );
  for (const item of s.items.reverse()) {
    const row = element("div", "", "item"),
      info = element("div", "");
    info.append(
      element("div", item.document || "Unreadable proposal", "item-title"),
      element("small", item.id.slice(0, 16) + " · " + item.stage),
    );
    row.append(info);
    const button = element(
      "button",
      item.stage === "Awaiting approval"
        ? "Review change"
        : item.stage === "Approval expired"
          ? "Review again"
          : item.stage === "Superseded"
            ? "Document changed since approval"
            : item.document_version !== undefined
              ? "Recover / refresh"
              : "Execute approved action",
      item.stage === "Awaiting approval" ? "" : "secondary",
    );
    button.disabled = s.paused || item.stage === "Superseded";
    button.onclick = () =>
      action(async () => {
        if (
          item.stage === "Awaiting approval" ||
          item.stage === "Approval expired"
        ) {
          let id = item.id;
          if (item.stage === "Approval expired")
            id = (await api("repropose", { id })).proposal_id;
          review = await api("review", { id });
          review.id = id;
          $("review-target").textContent =
            review.proposal.document +
            " · version " +
            review.proposal.expected_version +
            " → " +
            (review.proposal.expected_version + 1);
          $("review-content").textContent = review.proposal.content;
          $("review-digest").textContent = review.content_sha256;
          showPasskeyChallenge("");
          $("confirm").checked = false;
          $("approve").disabled = true;
          $("review").showModal();
        } else {
          say(
            "Checking the approved action and recovering any existing result…",
          );
          const r = await api("commit", { id: item.id });
          say(
            r.verification_status === "local_consistency_verified"
              ? "Document committed and evidence checked locally. Retrying did not create a second update."
              : r.execution_status === "committed"
                ? "The document is committed. Evidence needs recovery; retry this same action."
                : r.error_code === "admission_failed"
                  ? "The receiver refused this action. Nothing was changed: the approval is no longer valid for the current document."
                  : "The action was not confirmed. Retry the same approved action to recover its outcome.",
          );
          await refresh();
        }
      });
    row.append(button);
    $("items").append(row);
  }
  $("mode").textContent = s.paused
    ? s.rotation_message || "Admission paused for key handover."
    : s.paging
      ? "Incremental evidence enabled. Checkpoint completion is required before verification succeeds."
      : "Legacy full-package evidence. Enable incremental evidence to use bounded pages.";
  $("paging").hidden = s.paging;
  $("resume").hidden = !s.paused || !s.rotation_resumable;
  $("rotate").hidden = s.paused || s.remote_services;
  $("export").disabled = s.paused;
  $("passkey-status").textContent = s.passkey.configured
    ? "Passkey approvals are on for " +
      s.passkey.origin +
      ". Every approval needs a fresh, user-verified passkey gesture. Keep using this exact address."
    : s.passkey.available
      ? "Approvals are signed with a key file on this computer. Set up a passkey so that every approval also needs your fingerprint, face or device PIN."
      : "Passkeys need the localhost address. Open the app at its localhost link.";
  $("passkey-setup").hidden = s.passkey.configured || !s.passkey.available;
  $("passkey-setup").disabled = s.paused;
}
$("refresh").onclick = () => action(refresh);
$("paging").onclick = () =>
  action(async () => {
    await api("paging", {});
    await refresh();
    say("Incremental evidence enabled.");
  });
$("proposal-form").onsubmit = (e) => {
  e.preventDefault();
  action(async () => {
    const f = new FormData(e.target);
    const version = Number(f.get("expected_version"));
    if (!Number.isSafeInteger(version) || version < 0)
      throw Error("Enter a nonnegative document version.");
    await api("propose", {
      document: f.get("document"),
      expected_version: version,
      content: f.get("content"),
    });
    say("Proposal created. Review it before granting approval.");
    await refresh();
    $("activity").scrollIntoView({ behavior: "smooth" });
  });
};
$("confirm").onchange = () => {
  $("approve").disabled = !$("confirm").checked;
};
$("cancel").onclick = () => {
  $("review").close();
  review = null;
};
$("approve").onclick = () =>
  action(async () => {
    if (!review || !$("confirm").checked) return;
    const r = review;
    review = null;
    $("approve").disabled = true;
    try {
      const result = await api("approve", {
        id: r.id,
        review_token: r.review_token,
      });
      if (result.status === "passkey_required") {
        // The dialog keeps showing the exact content while the passkey prompt is open.
        showPasskeyChallenge(result.approval_sha256);
        say("Confirm with your passkey to approve this exact change.");
        let assertion;
        try {
          assertion = await passkeyAssertion(result);
        } catch {
          throw Error(
            "Passkey approval was not completed. Nothing was approved. Review the change again.",
          );
        }
        await api("approve/passkey", {
          id: r.id,
          assertion_token: result.assertion_token,
          assertion,
        });
      }
      say(
        "Exact change approved. Choose “Execute approved action” when ready.",
      );
    } finally {
      $("review").close();
      showPasskeyChallenge("");
      await refresh();
    }
  });
$("passkey-setup").onclick = () =>
  action(async () => {
    if (!window.PublicKeyCredential)
      throw Error("This browser does not support passkeys.");
    const begin = await api("passkey/register/begin", {});
    const credential = await navigator.credentials.create({
      publicKey: {
        rp: { id: begin.rp_id, name: "OpenProof" },
        user: {
          id: fromBase64url(begin.user_id),
          name: begin.user_name,
          displayName: "OpenProof owner",
        },
        challenge: fromBase64url(begin.challenge),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          userVerification: "required",
          residentKey: "preferred",
        },
        attestation: "none",
        timeout: 120000,
      },
    });
    const response = credential.response;
    if (response.getPublicKeyAlgorithm() !== -7)
      throw Error("The passkey must use ES256 (P-256).");
    const result = await api("passkey/register/finish", {
      credential_id: toBase64url(credential.rawId),
      client_data_json: toBase64url(response.clientDataJSON),
      authenticator_data: toBase64url(response.getAuthenticatorData()),
      public_key: toBase64url(response.getPublicKey()),
      algorithm: -7,
    });
    say(
      "Passkey set up (trust epoch " +
        result.installed_epoch +
        "). Every approval now needs your passkey.",
    );
    await refresh();
  });
action(async () => {
  const token = location.hash.slice(1);
  history.replaceState(null, "", "/");
  const session = token
    ? await api("session", { token })
    : await api("session");
  csrf = session.csrf;
  await refresh();
  const certificates = await api("certificates");
  say(
    "Your local workspace is ready. Approval and execution are separate steps." +
      (certificates.status === "attention" ||
      certificates.status === "configuration_unreadable"
        ? " Connection certificates need attention; check the Recovery center."
        : ""),
  );
});

$("rotate").onclick = () =>
  action(async () => {
    const confirmation = prompt(
      "This changes the locally owned root, receiver and witness keys. All approved actions must be resolved first. Admission pauses until completion. This is not compromise recovery. Type ROTATE LOCAL KEYS to prepare.",
    );
    if (confirmation !== "ROTATE LOCAL KEYS") return;
    await api("rotation/prepare", { confirmation });
    say(
      "Key change prepared. Admission is paused. Select Resume key change to apply or recover this exact plan.",
    );
    await refresh();
  });
$("resume").onclick = () =>
  action(async () => {
    await api("rotation/resume", {});
    say(
      "Planned key change completed. History and replay protection were retained.",
    );
    await refresh();
  });
$("export").onclick = () =>
  action(async () => {
    const r = await api("archive", {});
    const a = element("a", "Download your evidence package");
    a.href = r.download;
    a.download = "openproof-evidence.zip";
    $("export-result").replaceChildren(
      a,
      document.createTextNode(
        " · Share the trusted root and current checkpoint through a separate trusted channel. The package contains no private keys.",
      ),
    );
  });

const evidenceLabels = {
  none: "No checkpoint saved",
  needs_refresh: "Refresh needed",
  recent_record_only: "Recent saved checkpoint; refresh to verify",
};
const recoveryLabels = {
  committed: "Committed",
  approved_uncommitted: "Approved; not committed",
  expired_uncommitted: "Expired; no commit found",
  unconfirmed: "Outcome unconfirmed",
};
const certificateLabels = {
  valid: "Valid",
  expiring: "Renewal due soon",
  expired: "Expired",
  not_yet_valid: "Not yet valid",
  unreadable: "Could not inspect",
};
async function recoveryRefresh() {
  const r = await api("recovery");
  $("recovery-summary").textContent =
    "Receiver history: " +
    (r.heads.receiver ?? "unavailable") +
    " · Witness history: " +
    (r.heads.witness ?? "unavailable") +
    " · " +
    evidenceLabels[r.evidence.status] +
    ". " +
    (r.rotation.status === "not_paused"
      ? "Admission is open."
      : r.rotation.message);
  $("recovery-items").replaceChildren();
  if (!r.items.length)
    $("recovery-items").append(
      element("p", "No approved actions need inspection.", "muted"),
    );
  for (const item of r.items) {
    const row = element("div", "", "item"),
      text = element("div", "");
    text.append(
      element("div", item.document || "Unreadable action", "item-title"),
      element("small", recoveryLabels[item.status] + " · " + item.message),
    );
    row.append(text);
    if (item.can_recover) {
      const b = element("button", "Recover existing result", "secondary");
      b.onclick = () =>
        action(async () => {
          const result = await api("recover", { id: item.id });
          say(
            result.verification_status === "local_consistency_verified"
              ? "Existing result recovered and evidence checked locally. No new approval was granted."
              : "Existing commit retained; evidence still needs operator attention.",
          );
          await refresh();
          await recoveryRefresh();
        });
      row.append(b);
    }
    $("recovery-items").append(row);
  }
  $("certificate-summary").textContent =
    r.tls.status === "local_roles_no_tls"
      ? "Local roles do not use TLS. Remote certificates remain their operators’ responsibility."
      : r.tls.certificates
          .map(
            (c) =>
              c.role +
              " " +
              (c.kind === "client"
                ? "client certificate"
                : "trust certificate") +
              ": " +
              certificateLabels[c.status] +
              (c.not_after ? " · expires " + c.not_after : ""),
          )
          .join(" | ") || "Certificate configuration needs operator attention.";
  if (r.rotation.status !== "not_paused") {
    $("resume").hidden = !r.rotation.can_resume;
  }
}
$("recovery-refresh").onclick = () => action(recoveryRefresh);
