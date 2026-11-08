// End-to-end passkey check in a fresh local Chrome profile, using the built-in
// CDP virtual authenticator. No external network or production owner home is used.
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
const out = path.resolve(process.argv[2]);
fs.mkdirSync(out, { recursive: false, mode: 0o700 });
const root = path.resolve(import.meta.dirname, "..");
const python =
  process.env.OPENPROOF_PYTHON ||
  path.join(root, "outputs/local-venv/bin/python");
const witnessBinary = path.join(root, "target/debug/openproof-witness");
const home = path.join(out, "home");
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(test, what = "UI condition", tries = 300) {
  for (let i = 0; i < tries; i++) {
    if (await test()) return;
    await delay(100);
  }
  throw Error(what + " timeout");
}
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
    [
      "owner-app",
      "--home",
      home,
      "--session-file",
      path.join(out, name + "-session.json"),
      ...extra,
    ],
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
  if (r.status !== 0)
    throw Error(command + " failed: " + (r.stderr || "").slice(0, 500));
  return r.stdout;
}
function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}
function gate(...args) {
  return JSON.parse(run(witnessBinary, args));
}
// The receiver's own admission check, run directly. Returns the exit status.
function receive(request) {
  return spawnSync(
    witnessBinary,
    [
      "receive",
      path.join(home, "receiver/state"),
      path.join(home, "receiver/key.secret"),
      path.join(home, "trust.json"),
    ],
    { input: JSON.stringify(request), encoding: "utf8" },
  ).status;
}
const port = await freePort();
let app = startApp("app", ["--port", String(port)]);
let chrome, ws;
try {
  const first = await session("app");
  if (first.url.split("/#")[0] !== "http://localhost:" + port)
    throw Error("Owner app must advertise its localhost origin");
  const profile = path.join(out, "profile");
  const log = fs.openSync(path.join(out, "chrome.log"), "w");
  chrome = spawn(
    process.env.OPENPROOF_CHROME ||
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    [
      "--headless",
      // Containers run as root, where Chrome refuses its sandbox.
      ...(process.getuid?.() === 0 ? ["--no-sandbox"] : []),
      "--disable-gpu",
      "--disable-background-networking",
      "--no-first-run",
      "--remote-debugging-port=0",
      "--user-data-dir=" + profile,
      "about:blank",
    ],
    { stdio: ["ignore", log, log] },
  );
  await until(() => fs.existsSync(path.join(profile, "DevToolsActivePort")));
  const devtools = fs
    .readFileSync(path.join(profile, "DevToolsActivePort"), "utf8")
    .split("\n")[0];
  const tabs = await (
    await fetch("http://127.0.0.1:" + devtools + "/json")
  ).json();
  ws = new WebSocket(tabs.find((t) => t.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  let next = 0;
  const pending = new Map();
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id) {
      const p = pending.get(m.id);
      pending.delete(m.id);
      m.error ? p.reject(Error(m.error.message)) : p.resolve(m.result);
    }
  };
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = ++next;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });
  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (r.exceptionDetails)
      throw Error(
        "Browser evaluation failed: " +
          (r.exceptionDetails.exception?.description || expression),
      );
    return r.result.value;
  };
  const message = () =>
    evaluate("document.getElementById('message')?.textContent ?? ''");
  const screenshot = async (name) => {
    const png = await send("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: true,
    });
    fs.writeFileSync(path.join(out, name), Buffer.from(png.data, "base64"));
  };
  await send("Page.enable");
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
  await send("Emulation.setDeviceMetricsOverride", {
    width: 1440,
    height: 1300,
    deviceScaleFactor: 1,
    mobile: false,
  });
  const open = async (url) => {
    // Leave the page first: a hash-only change would not reload the app.
    await send("Page.navigate", { url: "about:blank" });
    await send("Page.navigate", { url });
    await until(
      async () => (await message()).includes("workspace is ready"),
      "workspace",
    );
  };
  await open(first.url);

  // 1. Register a passkey. This issues a new root-signed trust epoch.
  if (await evaluate("document.getElementById('passkey-setup').hidden"))
    throw Error("Passkey setup is not offered");
  await evaluate("document.getElementById('passkey-setup').click()");
  await until(
    async () => (await message()).includes("Passkey set up"),
    "passkey registration",
  );
  const credentials = await send("WebAuthn.getCredentials", {
    authenticatorId,
  });
  if (credentials.credentials.length !== 1)
    throw Error("Expected one registered passkey");
  const trust = readJson(path.join(home, "trust.json"));
  if (
    trust.owner_passkey?.origin !== "http://localhost:" + port ||
    trust.owner_passkey.rp_id !== "localhost" ||
    trust.owner_passkey.from_sequence !== 1
  )
    throw Error("Trust does not carry the registered passkey");
  if (!(await evaluate("document.getElementById('passkey-setup').hidden")))
    throw Error("Passkey setup still offered after registration");

  // 2. Propose, review and approve with the passkey.
  // The activity row for one item, found by its id prefix.
  const row = (id) =>
    "[...document.querySelectorAll('#items .item')].find((r) => r.querySelector('small')?.textContent.startsWith(" +
    JSON.stringify(id.slice(0, 16)) +
    "))";
  const approveWithPasskey = async (document, version, content) => {
    const before = new Set(
      (await evaluate("api('status')")).items.map((i) => i.id),
    );
    await evaluate(
      `document.querySelector('[name=document]').value=${JSON.stringify(document)};` +
        `document.querySelector('[name=expected_version]').value=${JSON.stringify(String(version))};` +
        `document.querySelector('[name=content]').value=${JSON.stringify(content)};` +
        "document.getElementById('proposal-form').requestSubmit()",
    );
    let id;
    await until(async () => {
      const items = (await evaluate("api('status')")).items;
      id = items.find((i) => !before.has(i.id))?.id;
      return id !== undefined;
    }, "proposal");
    await until(() =>
      evaluate(
        row(id) + "?.querySelector('button').textContent==='Review change'",
      ),
    );
    await evaluate(row(id) + ".querySelector('button').click()");
    await until(() => evaluate("document.getElementById('review').open"));
    // Record what the review screen shows at the moment the passkey is asked.
    await evaluate(`(() => {
      const original = navigator.credentials.get.bind(navigator.credentials);
      navigator.credentials.get = (options) => {
        window.atPrompt = {
          open: document.getElementById('review').open,
          content: document.getElementById('review-content').textContent,
          digest: document.getElementById('review-digest').textContent,
          approval: document.getElementById('review-approval').textContent,
          approvalVisible: !document.getElementById('review-approval').hidden,
          userVerification: options.publicKey.userVerification,
        };
        return original(options);
      };
    })()`);
    await evaluate(
      "document.getElementById('confirm').click();document.getElementById('approve').click()",
    );
    await until(
      () =>
        evaluate(
          row(id) +
            "?.querySelector('button').textContent==='Execute approved action'",
        ),
      "passkey approval",
    );
    return { id, prompt: await evaluate("window.atPrompt") };
  };
  const execute = async (id) => {
    await evaluate(row(id) + ".querySelector('button').click()");
    await until(
      () =>
        evaluate(
          row(id) +
            "?.querySelector('small').textContent.includes('Verified locally')",
        ),
      "execution",
    );
  };
  const content = "Passkey browser test <b>not markup</b> café";
  const { id: approvedId, prompt } = await approveWithPasskey(
    "passkey-fixture",
    0,
    content,
  );
  const contentSha = run("sha256sum", [], content).split(" ")[0];
  if (
    !prompt?.open ||
    prompt.content !== content ||
    prompt.digest !== contentSha ||
    !prompt.approvalVisible ||
    !/^[0-9a-f]{64}$/.test(prompt.approval) ||
    prompt.userVerification !== "required"
  )
    throw Error("Review screen did not show the exact content at the prompt");
  const approved = gate(
    "gate-approved",
    home,
    path.join(home, "trust.json"),
    approvedId,
  ).request;
  if (!approved.owner_assertion) throw Error("Stored request lacks assertion");
  const clientData = JSON.parse(
    Buffer.from(approved.owner_assertion.client_data_json, "base64url"),
  );
  if (
    Buffer.from(clientData.challenge, "base64url").toString("hex") !==
      prompt.approval ||
    clientData.origin !== "http://localhost:" + port ||
    clientData.type !== "webauthn.get"
  )
    throw Error("Assertion is not bound to the approval digest");

  // 3. Execute; the receiver checks the assertion, the verifier re-checks it.
  await execute(approvedId);
  await screenshot("after-execute.png");

  // 4. A process that can read the authority key cannot execute without the passkey.
  const forgedId = (
    await evaluate(
      "api('propose',{document:'passkey-fixture',expected_version:1,content:'forged without passkey'})",
    )
  ).proposal_id;
  const proposal = gate("gate-review", home, forgedId).proposal;
  const forged = JSON.parse(
    run(
      witnessBinary,
      [
        "approve",
        path.join(home, "authority/key.secret"),
        path.join(home, "trust.json"),
      ],
      JSON.stringify(proposal),
    ),
  );
  // A request file in the earlier approved/ folder is not read by the gate.
  const legacy = path.join(home, "approved");
  fs.mkdirSync(legacy, { mode: 0o700 });
  fs.writeFileSync(
    path.join(legacy, forgedId + ".json"),
    JSON.stringify(forged),
    {
      mode: 0o600,
    },
  );
  const forgedCommit = await evaluate(
    `api('commit',{id:${JSON.stringify(forgedId)}}).then(() => 'executed', () => 'refused')`,
  );
  // The receiver refuses it without an assertion and with a copied one.
  const withoutAssertion = receive(forged);
  const copiedAssertion = receive({
    ...forged,
    owner_assertion: approved.owner_assertion,
  });
  const recovery = await evaluate("api('recovery')");
  if (
    forgedCommit !== "refused" ||
    withoutAssertion === 0 ||
    copiedAssertion === 0 ||
    recovery.heads.receiver !== 1
  )
    throw Error("Request without a valid assertion was executed");
  fs.rmSync(legacy, { recursive: true });

  // 5. Export the history and verify it offline with the Go verifier.
  let go = process.env.OPENPROOF_GO_VERIFY;
  if (!go) {
    go = path.join(out, "openproof-go-verify");
    const tools = path.join(root, "outputs/tooling");
    const r = spawnSync("go", ["build", "-o", go, "."], {
      cwd: path.join(root, "reference/go-witness"),
      env: {
        ...process.env,
        GOMODCACHE: path.join(tools, "go-mod"),
        GOCACHE: path.join(tools, "go-cache"),
      },
      encoding: "utf8",
    });
    if (r.status !== 0) throw Error("go build failed: " + r.stderr);
  }
  const archive = await evaluate("api('archive',{})");
  const archiveDir = path.join(
    home,
    "exports",
    archive.download.split("/").pop(),
  );
  fs.copyFileSync(
    path.join(archiveDir, "checkpoint-copy.json"),
    path.join(out, "pin.json"),
  );
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
      go,
      "--out",
      path.join(out, "verify"),
    ]),
  );
  if (verified.status !== "portable_history_verified")
    throw Error("Offline verification failed");

  // 6. Restart without --port: the registered origin is reused, approvals still work.
  app.kill();
  await new Promise((resolve) => app.once("exit", resolve));
  app = startApp("app-restart", []);
  const second = await session("app-restart");
  if (second.url.split("/#")[0] !== "http://localhost:" + port)
    throw Error("Restart did not reuse the registered origin");
  await open(second.url);
  if (
    !(
      await evaluate("document.getElementById('passkey-status').textContent")
    ).includes("Passkey approvals are on")
  )
    throw Error("Passkey status not shown after restart");
  const again = await approveWithPasskey(
    "passkey-fixture",
    1,
    "Second passkey approval",
  );
  await execute(again.id);
  const final = await evaluate("api('recovery')");
  if (final.heads.receiver !== 2 || final.heads.witness !== 2)
    throw Error("Unexpected history length");
  await screenshot("app.png");
  const result = {
    passed: true,
    origin: "http://localhost:" + port,
    passkey_registered_with_virtual_authenticator: true,
    trust_epoch_with_passkey: trust.epoch,
    review_showed_exact_content_and_sha256_at_prompt: true,
    assertion_challenge_is_approval_digest: true,
    executed_and_verified_locally: true,
    request_without_assertion_executed: false,
    request_with_copied_assertion_executed: false,
    go_archive_verification: verified.status,
    restart_reused_origin: true,
    receiver_head: final.heads.receiver,
    external_model_calls: 0,
  };
  fs.writeFileSync(
    path.join(out, "result.json"),
    JSON.stringify(result, null, 2),
  );
  console.log(
    "Passkey workflow passed: registration, exact review, passkey approval, execution, fail-closed without assertion, offline verification, restart.",
  );
} finally {
  if (ws) ws.close();
  if (chrome) chrome.kill();
  app.kill();
}
