// End-to-end passkey check in a fresh local Chrome profile, using the built-in
// CDP virtual authenticator. No external network or production owner home is used.
//   OPENPROOF_CHROME=/path/to/chrome node scripts/passkey_smoke.mjs OUT_DIR
//
// Besides the normal flow, it changes the owner app's answer in flight, the way
// a defect on the server side could, and checks that the review page refuses
// before any passkey prompt (app/approval.js).
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { startChrome, until } from "./browser_cdp.mjs";
import { signingBytes } from "../app/approval.js";

const out = path.resolve(process.argv[2]);
fs.mkdirSync(out, { recursive: false, mode: 0o700 });
const root = path.resolve(import.meta.dirname, "..");
const python = process.env.OPENPROOF_PYTHON || path.join(root, "outputs/local-venv/bin/python");
const witnessBinary = path.join(root, "target/debug/openproof-witness");
const toolBinary = path.join(root, "target/debug/openproof-tool");
const home = path.join(out, "home");
const sha256 = (data) => crypto.createHash("sha256").update(data).digest("hex");

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}
function startApp(name, extra) {
  const log = fs.openSync(path.join(out, name + ".log"), "w");
  return spawn(
    witnessBinary,
    ["owner-app", "--home", home, "--session-file", path.join(out, name + "-session.json"), ...extra],
    { cwd: root, stdio: ["ignore", log, log] },
  );
}
async function session(name) {
  const file = path.join(out, name + "-session.json");
  // A restart on the same fixed port may wait for TIME_WAIT sockets to clear.
  await until(() => fs.existsSync(file), "owner app start", 1500);
  return JSON.parse(fs.readFileSync(file));
}
function run(command, args, input) {
  const r = spawnSync(command, args, { input, cwd: root, encoding: "utf8" });
  if (r.status !== 0) throw Error(command + " failed: " + (r.stderr || "").slice(0, 500));
  return r.stdout;
}
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const gate = (...args) => JSON.parse(run(witnessBinary, args));
const state = (id) => gate("gate-approved", home, path.join(home, "trust.json"), id).state;
// The receiver's own admission check, run directly. Returns the exit status.
const receive = (request) =>
  spawnSync(
    witnessBinary,
    ["receive", path.join(home, "receiver/state"), path.join(home, "receiver/key.secret"), path.join(home, "trust.json")],
    { input: JSON.stringify(request), encoding: "utf8" },
  ).status;

const port = await freePort();
let app = startApp("app", ["--port", String(port)]);
let b;
try {
  const first = await session("app");
  // The review origin is the passkey's; the workspace runs on another port.
  const reviewOrigin = first.review_origin;
  let workspaceOrigin = first.url.split("/#")[0];
  if (reviewOrigin !== "http://localhost:" + port || !workspaceOrigin.startsWith("http://localhost:") || workspaceOrigin === reviewOrigin)
    throw Error("Owner app must advertise two localhost origins");
  b = await startChrome(out);
  const { send, evaluate, api } = b;
  const message = () => evaluate("document.getElementById('message')?.textContent ?? ''");
  await send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  const go = async (url, ready) => {
    // Leave the page first: a hash-only change would not reload it.
    await send("Page.navigate", { url: "about:blank" });
    await send("Page.navigate", { url });
    await until(ready, url);
  };
  // The workspace ignores clicks while an operation runs, start-up included.
  const workspace = (url) =>
    go(
      url,
      async () =>
        (await message()).includes("workspace is ready") &&
        (await evaluate("document.body.dataset.state === 'idle'")),
    );
  await workspace(first.url);

  // 1. Register a passkey on its own page. This issues a new root-signed trust epoch.
  if (await evaluate("document.getElementById('passkey-setup').hidden"))
    throw Error("Passkey setup is not offered");
  await evaluate("document.getElementById('passkey-setup').click()");
  await until(() => evaluate("location.pathname==='/setup' && document.getElementById('setup')?.disabled === false"), "setup page");
  const setupScripts = await evaluate(
    "performance.getEntriesByType('resource').map((e) => new URL(e.name).pathname).filter((p) => p.endsWith('.js')).sort()",
  );
  if (JSON.stringify(setupScripts) !== JSON.stringify(["/common.js", "/setup.js"]))
    throw Error("Setup page loaded other scripts: " + setupScripts);
  await evaluate("document.getElementById('setup').click()");
  await until(async () => (await message()).includes("Passkey set up"), "passkey registration");
  const credentials = await send("WebAuthn.getCredentials", { authenticatorId });
  if (credentials.credentials.length !== 1) throw Error("Expected one registered passkey");
  const trust = readJson(path.join(home, "trust.json"));
  if (
    trust.owner_passkey?.origin !== "http://localhost:" + port ||
    trust.owner_passkey.rp_id !== "localhost" ||
    trust.owner_passkey.from_sequence !== 1
  )
    throw Error("Trust does not carry the registered passkey");
  if (!(await evaluate("document.getElementById('passkey-setup').hidden")))
    throw Error("Passkey setup still offered after registration");

  // Record what the review page shows when the passkey is asked, and how often.
  const watchPrompt = () =>
    evaluate(`(() => {
      window.prompts = 0;
      const original = navigator.credentials.get.bind(navigator.credentials);
      navigator.credentials.get = (options) => {
        window.prompts += 1;
        window.atPrompt = {
          content: document.getElementById('review-content').textContent,
          digest: document.getElementById('review-digest').textContent,
          approval: document.getElementById('review-approval').textContent,
          approvalVisible: !document.getElementById('review-approval').hidden,
          challenge: Array.from(new Uint8Array(options.publicKey.challenge), (x) => x.toString(16).padStart(2, '0')).join(''),
          userVerification: options.publicKey.userVerification,
        };
        return original(options);
      };
    })()`);
  const propose = async (document, version, content) => {
    if ((await evaluate("location.origin")) !== workspaceOrigin) await workspace(workspaceOrigin + "/");
    return (await api("propose", { document, expected_version: version, content })).proposal_id;
  };
  const openReview = async (id) => {
    await go(reviewOrigin + "/review#" + id, () =>
      evaluate("document.getElementById('review')?.hidden === false"),
    );
    await watchPrompt();
  };
  const clickApprove = () =>
    evaluate("document.getElementById('confirm').click();document.getElementById('approve').click()");

  // 2. Propose, review on the review page and approve with the passkey.
  const content = "Passkey browser test <b>not markup</b> café";
  const approvedId = await propose("passkey-fixture", 0, content);
  await openReview(approvedId);
  await clickApprove();
  await until(
    async () => (await evaluate("location.pathname")) === "/" && (await message()).includes("Approved."),
    "passkey approval",
  );
  // The prompt record is lost with the page; read it from the stored request instead.
  const approved = gate("gate-approved", home, path.join(home, "trust.json"), approvedId).request;
  if (!approved.owner_assertion) throw Error("Stored request lacks assertion");
  const clientData = JSON.parse(Buffer.from(approved.owner_assertion.client_data_json, "base64url"));
  const digest = sha256(signingBytes(approved.approval.payload));
  if (
    Buffer.from(clientData.challenge, "base64url").toString("hex") !== digest ||
    clientData.origin !== "http://localhost:" + port ||
    clientData.type !== "webauthn.get" ||
    approved.approval.payload.content_sha256 !== sha256(content)
  )
    throw Error("Assertion is not bound to the approval digest");

  // 3. What the page shows at the prompt: the exact content, its digest, the challenge.
  const secondId = await propose("passkey-other", 0, content + " (second)");
  await openReview(secondId);
  await evaluate(`(() => {
    const original = navigator.credentials.get;
    navigator.credentials.get = (o) => { window.held = original(o); return new Promise(() => {}); };
  })()`);
  await clickApprove();
  await until(() => evaluate("window.prompts === 1"), "prompt").catch(async (e) => {
    throw Error(e.message + ": " + (await message()) + " prompts=" + (await evaluate("window.prompts")));
  });
  const prompt = await evaluate("window.atPrompt");
  if (
    prompt.content !== content + " (second)" ||
    prompt.digest !== sha256(content + " (second)") ||
    !prompt.approvalVisible ||
    prompt.approval !== prompt.challenge ||
    !/^[0-9a-f]{64}$/.test(prompt.challenge) ||
    prompt.userVerification !== "required"
  )
    throw Error("Review page did not show the exact change at the prompt: " + JSON.stringify(prompt));
  if (state(secondId) !== "awaiting_passkey") throw Error("Approval stored without the assertion");

  // 4. A changed answer from the server never reaches the passkey.
  const tamper = async (name, change) => {
    const id = await propose("passkey-tamper", 0, "tamper test " + name);
    await openReview(id);
    await send("Fetch.enable", { patterns: [{ urlPattern: "*/api/approve", requestStage: "Response" }] });
    const done = new Promise((resolve) =>
      b.on("Fetch.requestPaused", async (e) => {
        const r = await send("Fetch.getResponseBody", { requestId: e.requestId });
        const body = JSON.parse(r.base64Encoded ? Buffer.from(r.body, "base64").toString() : r.body);
        change(body);
        await send("Fetch.fulfillRequest", {
          requestId: e.requestId,
          responseCode: e.responseStatusCode,
          responseHeaders: e.responseHeaders,
          body: Buffer.from(JSON.stringify(body)).toString("base64"),
        });
        resolve();
      }),
    );
    await clickApprove();
    await done;
    await until(async () => (await message()).includes("does not match"), "refusal: " + name);
    await send("Fetch.disable");
    if ((await evaluate("window.prompts")) !== 0) throw Error("Passkey prompted after tampering: " + name);
    if (state(id) === "approved") throw Error("Tampered approval was stored: " + name);
  };
  // As if the gate had signed other content and reported that approval's own digest.
  await tamper("content", (r) => {
    r.approval.content_sha256 = sha256("other content");
    r.approval_sha256 = sha256(signingBytes(r.approval));
  });
  await tamper("document", (r) => {
    r.approval.document = "other-document";
    r.approval_sha256 = sha256(signingBytes(r.approval));
  });
  await tamper("version", (r) => {
    r.approval.expected_version = 5;
    r.approval_sha256 = sha256(signingBytes(r.approval));
  });
  await tamper("digest only", (r) => {
    r.approval_sha256 = sha256("other");
  });

  // 5. Execute; the receiver checks the assertion.
  await workspace(workspaceOrigin + "/");
  const row = (id) =>
    "[...document.querySelectorAll('.item')].find((r) => r.querySelector('.item-meta')?.textContent.includes(" +
    JSON.stringify(id.slice(0, 12)) +
    "))";
  const execute = async (id) => {
    await until(() => evaluate("document.body.dataset.state === 'idle'"), "idle");
    await until(() => evaluate(row(id) + "?.querySelector('button')?.textContent==='Execute approved action'"), "execute button");
    await evaluate(row(id) + ".querySelector('button').click()");
    await until(async () => (await api("status")).items.find((i) => i.id === id)?.stage === "Verified locally", "execution");
  };
  await execute(approvedId);
  await b.screenshot(path.join(out, "after-execute.png"));

  // 6. A process that can read the authority key cannot execute without the passkey.
  const forgedId = await propose("passkey-fixture", 1, "forged without passkey");
  const proposal = gate("gate-review", home, forgedId).proposal;
  const forged = JSON.parse(
    run(toolBinary, ["approve", path.join(home, "authority/key.secret"), path.join(home, "trust.json")], JSON.stringify(proposal)),
  );
  const forgedCommit = await api("commit", { id: forgedId }).then(() => "executed", () => "refused");
  const withoutAssertion = receive(forged);
  const copiedAssertion = receive({ ...forged, owner_assertion: approved.owner_assertion });
  const recovery = await api("recovery");
  if (forgedCommit !== "refused" || withoutAssertion === 0 || copiedAssertion === 0 || recovery.heads.receiver !== 1)
    throw Error("Request without a valid assertion was executed");

  // 7. Export the history and verify it offline with the Go verifier.
  let goVerify = process.env.OPENPROOF_GO_VERIFY;
  if (!goVerify) {
    goVerify = path.join(out, "openproof-go-verify");
    const tools = path.join(root, "outputs/tooling");
    const r = spawnSync("go", ["build", "-o", goVerify, "."], {
      cwd: path.join(root, "reference/go-witness"),
      env: { ...process.env, GOMODCACHE: path.join(tools, "go-mod"), GOCACHE: path.join(tools, "go-cache") },
      encoding: "utf8",
    });
    if (r.status !== 0) throw Error("go build failed: " + r.stderr);
  }
  const archive = await api("archive", {});
  const archiveDir = path.join(home, "exports", archive.download.split("/").pop());
  fs.copyFileSync(path.join(archiveDir, "checkpoint-copy.json"), path.join(out, "pin.json"));
  const rootKey = readJson(path.join(home, "root-public.json")).public_key;
  const verified = JSON.parse(
    run(python, [
      path.join(root, "scripts/verify_history.py"),
      archiveDir,
      "--root",
      rootKey,
      "--checkpoint",
      path.join(out, "pin.json"),
      "--go-binary",
      goVerify,
      "--out",
      path.join(out, "verify"),
    ]),
  );
  if (verified.status !== "portable_history_verified") throw Error("Offline verification failed");

  // 8. Restart without --port: the registered origin is reused, approvals still work.
  app.kill();
  await new Promise((resolve) => app.once("exit", resolve));
  app = startApp("app-restart", []);
  const second = await session("app-restart");
  if (second.review_origin !== reviewOrigin) throw Error("Restart did not reuse the registered origin");
  await workspace(second.url);
  workspaceOrigin = second.url.split("/#")[0];
  if (!(await evaluate("document.getElementById('passkey-status').textContent")).includes("Every approval needs"))
    throw Error("Passkey status not shown after restart");
  const againId = await propose("passkey-fixture", 1, "Second passkey approval");
  await openReview(againId);
  await clickApprove();
  await until(async () => (await message()).includes("Approved."), "second approval");
  await execute(againId);
  const final = await api("recovery");
  if (final.heads.receiver !== 2 || final.heads.witness !== 2) throw Error("Unexpected history length");
  await b.screenshot(path.join(out, "app.png"));
  const result = {
    passed: true,
    origin: "http://localhost:" + port,
    passkey_registered_on_its_own_page: true,
    trust_epoch_with_passkey: trust.epoch,
    review_showed_exact_content_and_sha256_at_prompt: true,
    challenge_computed_by_the_page_from_the_checked_approval: true,
    tampered_answers_refused_before_prompt: ["content", "document", "version", "digest only"],
    executed_and_verified_locally: true,
    request_without_assertion_executed: false,
    request_with_copied_assertion_executed: false,
    go_archive_verification: verified.status,
    restart_reused_origin: true,
    receiver_head: final.heads.receiver,
    external_model_calls: 0,
  };
  fs.writeFileSync(path.join(out, "result.json"), JSON.stringify(result, null, 2));
  console.log(
    "Passkey workflow passed: registration, exact review, page-computed challenge, tampering refused, execution, fail-closed without assertion, offline verification, restart.",
  );
} finally {
  if (b) b.close();
  app.kill();
}
