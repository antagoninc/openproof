// OpenProof owner workspace: the dashboard. Every value from the server is
// rendered as text, never as HTML. Approval and execution stay two separate
// owner decisions.
//
// This page is not trusted for what the owner approves: the review happens on
// its own page (review.js), and passkey set-up on another (setup.js). No code
// from this file runs on either. See docs/TCB.md.
import { $, el, say, api, startSession } from "./common.js";
import { sha256Text } from "./approval.js";

let busy = false,
  status = null,
  reviewOrigin = "";

// One owner operation at a time. The button that started it shows progress.
async function action(fn, button) {
  if (busy) return;
  busy = true;
  // Also in the page, so that a check can wait for the operation to end.
  document.body.dataset.state = "busy";
  if (button) {
    button.classList.add("busy");
    button.setAttribute("aria-busy", "true");
  }
  try {
    await fn();
  } catch (e) {
    say(e.message, "bad");
  } finally {
    busy = false;
    document.body.dataset.state = "idle";
    if (button) {
      button.classList.remove("busy");
      button.removeAttribute("aria-busy");
    }
  }
}

function tone(e, value) {
  if (value) e.dataset.tone = value;
  return e;
}

/** Open the review page for one proposal. An expired approval is proposed again first. */
async function openReview(item) {
  let id = item.id;
  if (item.stage === "Approval expired")
    id = (await api("repropose", { id })).proposal_id;
  location.assign(reviewOrigin + "/review#" + id);
}

// ---------------------------------------------------------------- actions

const STEPS = ["Proposed", "Approved", "Executed", "Checked"];
// at: the first step not yet done. mark: how that step is shown.
const STAGES = {
  "Awaiting approval": {
    badge: "Needs review",
    tone: "attention",
    at: 1,
    mark: "current",
    queue: true,
    act: "review",
    label: "Review change",
    primary: true,
  },
  "Approval expired": {
    badge: "Approval expired",
    tone: "attention",
    at: 1,
    mark: "warn",
    queue: true,
    act: "review",
    label: "Review again",
    note: "The approval expired before execution. Review the change again for a fresh approval.",
  },
  Approved: {
    badge: "Approved",
    tone: "ready",
    at: 2,
    mark: "current",
    queue: true,
    act: "commit",
    label: "Execute approved action",
    primary: true,
  },
  Superseded: {
    badge: "Superseded",
    tone: "bad",
    at: 2,
    mark: "stop",
    queue: false,
    act: null,
    label: "Document changed since approval",
    note: "The document changed after this approval, so the receiver would refuse it. Propose again from the current version.",
  },
  "Needs recovery": {
    badge: "Needs recovery",
    tone: "bad",
    at: 2,
    mark: "warn",
    queue: true,
    act: "commit",
    label: "Recover / refresh",
    note: "Its state could not be read. Recover the outcome of this same action. This grants nothing new.",
  },
  Committed: {
    badge: "Executed",
    tone: "ready",
    at: 3,
    mark: "warn",
    queue: true,
    act: "commit",
    label: "Recover / refresh",
    note: "The document is updated. Its evidence is not checked yet: refresh to finish the check.",
  },
  "Evidence needs refresh": {
    badge: "Check is old",
    tone: "done",
    at: 3,
    mark: "warn",
    queue: false,
    act: "commit",
    label: "Recover / refresh",
  },
  "Verified locally": {
    badge: "Checked locally",
    tone: "done",
    at: 4,
    mark: "done",
    queue: false,
    act: "commit",
    label: "Recover / refresh",
  },
};
const FALLBACK = {
  badge: "Unknown state",
  tone: "bad",
  at: 0,
  mark: "warn",
  queue: true,
  act: null,
  label: "",
};

function stepper(stage) {
  const list = el("ol", null, "steps");
  list.setAttribute("aria-label", "Progress");
  STEPS.forEach((name, i) => {
    const li = el("li");
    li.dataset.state = i < stage.at ? "done" : i === stage.at ? stage.mark : "todo";
    li.append(el("i"), el("span", name));
    list.append(li);
  });
  return list;
}

function itemRow(item) {
  const stage = STAGES[item.stage] || FALLBACK;
  const row = tone(el("div", null, "item"), stage.queue ? stage.tone : "");
  const main = el("div", null, "item-main");
  const top = el("div", null, "item-top");
  top.append(
    el("span", item.document || "Unreadable proposal", "item-title"),
    tone(el("span", stage.badge, "badge"), stage.tone),
  );
  const version = Number.isSafeInteger(item.expected_version)
    ? "v" + item.expected_version + " → v" + (item.expected_version + 1)
    : "";
  main.append(
    top,
    el("span", [version, item.id.slice(0, 12)].filter(Boolean).join(" · "), "item-meta"),
    stepper(stage),
  );
  if (stage.note) main.append(el("p", stage.note, "item-note"));
  row.append(main);
  if (stage.label) {
    const actions = el("div", null, "item-actions");
    const button = el(
      "button",
      stage.label,
      stage.primary ? "primary" : stage.queue ? "secondary" : "ghost",
    );
    button.type = "button";
    button.disabled = status.paused || !stage.act;
    button.onclick = () =>
      action(
        () => (stage.act === "review" ? openReview(item) : execute(item)),
        button,
      );
    actions.append(button);
    row.append(actions);
  }
  return row;
}

function emptyQueue(hasHistory) {
  const box = el("div", null, "empty");
  if (hasHistory) {
    box.append(
      el("strong", "Nothing needs you right now."),
      el("span", "New proposals from your agents appear here for review."),
    );
    return box;
  }
  const flow = el("ol", null, "flow");
  [
    ["1", "Propose the exact text"],
    ["2", "Review and approve it"],
    ["3", "Execute and check"],
  ].forEach(([n, t]) => {
    const li = el("li");
    li.append(el("b", n), document.createTextNode(t));
    flow.append(li);
  });
  const start = el("button", "Create your first change", "primary");
  start.type = "button";
  start.onclick = openCompose;
  box.append(
    el("strong", "Your first verified action"),
    flow,
    el(
      "span",
      "Each step is a separate decision. Retrying recovers an existing result; it never grants a new approval.",
      "fine",
    ),
    start,
  );
  return box;
}

function chip(text, value) {
  return tone(el("li", text, "chip"), value);
}

async function refresh() {
  const s = await api("status");
  status = s;
  const count = (f) => s.items.filter(f).length;
  $("pending").textContent = count(
    (x) => x.stage === "Awaiting approval" || x.stage === "Approval expired",
  );
  $("ready").textContent = count((x) => x.stage === "Approved");
  $("committed").textContent = count((x) => x.document_version !== undefined);
  $("verified").textContent = count((x) => x.stage === "Verified locally");

  const newest = s.items.slice().reverse();
  const queue = newest.filter((x) => (STAGES[x.stage] || FALLBACK).queue);
  const history = newest.filter((x) => !(STAGES[x.stage] || FALLBACK).queue);
  $("items").replaceChildren(
    ...(queue.length ? queue.map(itemRow) : [emptyQueue(history.length > 0)]),
  );
  $("history").replaceChildren(
    ...(history.length
      ? history.map(itemRow)
      : [el("p", "Executed and closed actions appear here.", "quiet-empty")]),
  );

  $("chips").replaceChildren(
    chip("Local only", "good"),
    s.passkey.configured
      ? chip("Passkey on", "good")
      : chip("Passkey off", "warn"),
    s.remote_services
      ? chip("Separate role services", "good")
      : chip("Roles share this account", ""),
    s.paused ? chip("Admission paused", "bad") : chip("Admission open", "good"),
    ...(s.trust.expired ? [chip("Trust expired", "bad")] : []),
  );

  // The trust lasts one day. Nothing is approved or executed after it expires.
  const until = s.trust.expires_at
    ? new Date(s.trust.expires_at * 1000).toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      })
    : "an unknown time";
  const left = (s.trust.expires_at || 0) - Date.now() / 1000;
  $("trust-summary").textContent = s.trust.expired
    ? "The trust expired on " +
      until +
      ". Approvals and execution are refused until you renew it."
    : "The trust is valid until " + until + ". It lasts one day.";
  $("renew").hidden = !s.trust.expired && left > 2 * 3600;

  // Names the owner has used, for the proposal form.
  $("known-documents").replaceChildren(
    ...s.documents.map((name) => {
      const option = document.createElement("option");
      option.value = name;
      return option;
    }),
  );
  // Protected files (docs/PROTECTED-FILES.md), as the receiver service
  // reports them. The check is local_roles.py status.
  const files = s.published;
  $("files-summary").hidden = !files;
  $("files-summary").textContent = !files
    ? ""
    : !Array.isArray(files.not_published)
      ? "Protected files: the receiver did not accept the folder. Run local_roles.py status."
      : files.not_published.length
        ? "Protected files are in " +
          files.folder +
          ". Not written as current files: " +
          files.not_published.join(", ") +
          "."
        : "Protected files are in " + files.folder + ". All files are current.";

  $("mode").textContent = s.paused
    ? s.rotation_message || "Admission paused for key handover."
    : s.paging
      ? "Incremental evidence is on. A matching checkpoint is required before a check succeeds."
      : "Full-package evidence. Turn on incremental evidence to use bounded pages.";
  $("paging").hidden = s.paging;
  $("export").disabled = s.paused;
  $("new-change").disabled = s.paused;

  const badge = $("passkey-badge");
  badge.textContent = s.passkey.configured ? "On" : "Off";
  badge.dataset.tone = s.passkey.configured ? "good" : "attention";
  $("passkey-status").textContent = s.passkey.configured
    ? "Every approval needs a fresh, user-verified gesture on your passkey for " +
      s.passkey.origin +
      ". Keep using this exact address."
    : s.passkey.available
      ? "Approvals are signed with a key file on this computer. Set up a passkey so every approval also needs your fingerprint, face or device PIN."
      : "Passkeys need the localhost address. Open the app at its localhost link.";
  $("passkey-setup").hidden = s.passkey.configured || !s.passkey.available;
  $("passkey-setup").disabled = s.paused;
}

async function execute(item) {
  say("Checking the approved action and recovering any existing result…");
  const r = await api("commit", { id: item.id });
  if (r.verification_status === "local_consistency_verified")
    say(
      "Executed and checked locally. Retrying never creates a second update.",
    );
  else if (r.execution_status === "committed")
    say(
      "The document is updated. Its evidence needs recovery: select Recover / refresh on the same action.",
      "bad",
    );
  else if (r.error_code === "admission_failed")
    say(
      "The receiver refused this action. Nothing changed: the approval is no longer valid for the current document.",
      "bad",
    );
  else
    say(
      "The action was not confirmed. Retry the same approved action to recover its outcome.",
      "bad",
    );
  await refresh();
  await quietHealth();
}

// Health after a change; a failure shows in the panel, not as an error.
async function quietHealth() {
  try {
    await recoveryRefresh();
  } catch {
    $("recovery-summary").textContent =
      "Health is unavailable right now. Select Check recovery to try again.";
  }
}

// ---------------------------------------------------------------- compose

let versionTimer = 0;
// The text that this page put in the text box, if the owner has not changed it.
let loadedText = "";
function fileHint(name) {
  const files = status && status.published;
  if (!files) return "";
  let hint = /[A-Z]/.test(name)
    ? "A name with a capital letter is not written as a protected file."
    : "Protected file: " + files.folder + "/" + name;
  if (/(settings|json)$/.test(name))
    hint += " The text must be a JSON object, because of the name.";
  return hint;
}
async function fillCurrentVersion() {
  const form = $("proposal-form");
  const name = form.elements.document.value.trim();
  const hint = $("version-hint");
  $("file-hint").hidden = true;
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(name)) {
    hint.textContent = name
      ? "Use 1 to 80 letters, digits, hyphens or underscores."
      : "Type a new name to make a document, or the name of a document to change it.";
    return;
  }
  $("file-hint").textContent = fileHint(name);
  $("file-hint").hidden = !$("file-hint").textContent;
  try {
    const r = await api("current-version", { document: name });
    if (form.elements.document.value.trim() !== name) return;
    if (Number.isSafeInteger(r.version)) {
      form.elements.expected_version.value = String(r.version);
      const box = form.elements.content;
      const untouched = box.value === "" || box.value === loadedText;
      if (untouched) {
        // Edit the current text instead of typing it again.
        loadedText = typeof r.content === "string" ? r.content : "";
        box.value = loadedText;
        updateDigest();
      }
      hint.textContent =
        r.version === 0
          ? "New document. It will be created at version 1."
          : "The receiver holds version " +
            r.version +
            ". This change makes version " +
            (r.version + 1) +
            (untouched && loadedText
              ? ". The current text is in the box below: change it there."
              : ".");
    } else {
      hint.textContent =
        "The receiver did not answer. Enter the current version yourself.";
    }
  } catch {
    hint.textContent = "";
  }
}
async function updateDigest() {
  const text = $("proposal-form").elements.content.value;
  const bytes = new TextEncoder().encode(text).length;
  $("content-size").textContent =
    bytes.toLocaleString() + (bytes === 1 ? " byte" : " bytes");
  try {
    $("content-digest").textContent = text ? await sha256Text(text) : "—";
  } catch {
    $("content-digest").textContent = "unavailable";
  }
}
function openCompose() {
  if (status && status.paused) return;
  $("compose").showModal();
  fillCurrentVersion();
  updateDigest();
  const form = $("proposal-form").elements;
  (form.document.value ? form.content : form.document).focus();
}
$("new-change").onclick = openCompose;
const docField = $("proposal-form").elements.document;
docField.addEventListener("input", () => {
  clearTimeout(versionTimer);
  versionTimer = setTimeout(fillCurrentVersion, 350);
});
docField.addEventListener("change", fillCurrentVersion);
$("proposal-form").elements.content.addEventListener("input", updateDigest);
$("proposal-form").onsubmit = (e) => {
  e.preventDefault();
  const submit = e.target.querySelector("button[type=submit]");
  action(async () => {
    const f = new FormData(e.target);
    const version = Number(f.get("expected_version"));
    if (!Number.isSafeInteger(version) || version < 0)
      throw Error("Enter a nonnegative document version.");
    const r = await api("propose", {
      document: f.get("document"),
      expected_version: version,
      content: f.get("content"),
    });
    $("compose").close();
    e.target.elements.content.value = "";
    e.target.elements.document.value = "";
    loadedText = "";
    await refresh();
    say("Proposal created. Review it before you approve anything.");
    const id = r && r.proposal_id;
    const item = id && status.items.find((x) => x.id === id);
    if (item) await openReview(item);
  }, submit);
};
for (const b of document.querySelectorAll("[data-close]"))
  b.onclick = () => $(b.dataset.close).close();

// ---------------------------------------------------------------- rail

$("refresh").onclick = () =>
  action(async () => {
    await refresh();
    say("Up to date.");
  }, $("refresh"));

$("paging").onclick = () =>
  action(async () => {
    await api("paging", {});
    await refresh();
    say("Incremental evidence is on.");
  }, $("paging"));

$("passkey-setup").onclick = () => location.assign(reviewOrigin + "/setup");

$("export").onclick = () =>
  action(async () => {
    const r = await api("archive", {});
    const a = el("a", "Download evidence package");
    a.href = r.download;
    a.download = "openproof-evidence.zip";
    $("export-result").replaceChildren(
      a,
      document.createTextNode(
        ". It holds no private keys. Share the trusted root and a current checkpoint through a separate trusted channel.",
      ),
    );
    say("Evidence package ready.");
  }, $("export"));

const evidenceLabels = {
  none: "No checkpoint saved",
  needs_refresh: "Refresh needed",
  recent_record_only: "Recent; refresh to verify",
};
const recoveryLabels = {
  committed: "Committed",
  approved_uncommitted: "Approved, not committed",
  expired_uncommitted: "Expired, no commit found",
  unconfirmed: "Outcome unconfirmed",
};
function kv(list, pairs) {
  list.replaceChildren();
  for (const [k, v] of pairs) list.append(el("dt", k), el("dd", v));
  list.hidden = false;
}

async function recoveryRefresh() {
  const r = await api("recovery");
  kv($("health-list"), [
    ["Receiver history", String(r.heads.receiver ?? "unavailable")],
    ["Witness history", String(r.heads.witness ?? "unavailable")],
    ["Evidence", evidenceLabels[r.evidence.status] || r.evidence.status],
    [
      "Admission",
      r.rotation.status === "not_paused" ? "Open" : "Paused",
    ],
  ]);
  $("recovery-summary").textContent =
    r.rotation.status === "not_paused"
      ? "Recovery refreshes an existing result. It cannot approve or execute anything."
      : r.rotation.message;
  // Committed actions recover from their own row; list only the rest here.
  const items = r.items.filter((x) => x.status !== "committed");
  $("recovery-items").replaceChildren(
    ...items.slice(0, 6).map((item) => {
      const box = el("div", null, "mini");
      const top = el("div", null, "item-top");
      top.append(
        el("span", item.document || "Unreadable action", "item-title"),
        tone(
          el("span", recoveryLabels[item.status] || item.status, "badge"),
          item.status === "committed" ? "done" : "attention",
        ),
      );
      box.append(top, el("span", item.message, "fine"));
      if (item.can_recover) {
        const b = el("button", "Recover existing result", "secondary");
        b.type = "button";
        b.onclick = () =>
          action(async () => {
            const result = await api("recover", { id: item.id });
            say(
              result.verification_status === "local_consistency_verified"
                ? "Existing result recovered and checked locally. No new approval was granted."
                : "Existing commit kept. Its evidence still needs operator attention.",
              result.verification_status === "local_consistency_verified"
                ? ""
                : "bad",
            );
            await refresh();
            await recoveryRefresh();
          }, b);
        box.append(b);
      }
      return box;
    }),
  );
  $("services-summary").textContent =
    r.services === "separate_accounts"
      ? "The receiver and the witness run under their own accounts. Check them with local_roles.py status."
      : "The receiver and the witness run in this account. See LOCAL-ROLES.md to separate them.";
}
$("renew").onclick = () =>
  action(async () => {
    await api("renew", {});
    await refresh();
    say("Trust renewed for one day. Your keys, passkey and history are unchanged.");
    await quietHealth();
  }, $("renew"));

$("recovery-refresh").onclick = () =>
  action(async () => {
    await recoveryRefresh();
    say("Health checked.");
  }, $("recovery-refresh"));

// ---------------------------------------------------------------- start

// The fragment holds the launcher's session token, or a note from another page.
const NOTES = {
  approved: "Approved. Select “Execute approved action” when you are ready.",
  passkey: "Passkey set up. Every approval now needs your passkey.",
};
action(async () => {
  const fragment = location.hash.slice(1);
  history.replaceState(null, "", "/");
  reviewOrigin = (await startSession(NOTES[fragment] ? "" : fragment)).review;
  await refresh();
  if (status.trust.expired && !NOTES[fragment])
    say("The trust expired. Select Renew trust under Health to continue.", "bad");
  else
    say(
      NOTES[fragment] ||
        "Your workspace is ready. Approval and execution are separate steps.",
    );
  await quietHealth();
});
