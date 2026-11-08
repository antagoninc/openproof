// Browser-level fixture check using a fresh local Chrome profile and built-in CDP.
// No external network or production owner home is used.
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
const out = path.resolve(process.argv[2]);
fs.mkdirSync(out, { recursive: false, mode: 0o700 });
const root = path.resolve(import.meta.dirname, "..");
const python =
  process.env.OPENPROOF_PYTHON ||
  path.join(root, "outputs/local-venv/bin/python");
const appLog = fs.openSync(path.join(out, "app.log"), "w");
const app = spawn(
  python,
  [
    path.join(root, "scripts/owner_app.py"),
    "--home",
    path.join(out, "home"),
    "--session-file",
    path.join(out, "session.json"),
  ],
  { cwd: root, stdio: ["ignore", appLog, appLog] },
);
let chrome, ws;
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(test) {
  for (let i = 0; i < 200; i++) {
    if (await test()) return;
    await delay(100);
  }
  throw Error("UI condition timeout");
}
try {
  await until(() => fs.existsSync(path.join(out, "session.json")));
  const session = JSON.parse(fs.readFileSync(path.join(out, "session.json")));
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
  const port = fs
    .readFileSync(path.join(profile, "DevToolsActivePort"), "utf8")
    .split("\n")[0];
  const tabs = await (await fetch("http://127.0.0.1:" + port + "/json")).json();
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
    if (r.exceptionDetails) throw Error("Browser evaluation failed");
    return r.result.value;
  };
  await send("Page.enable");
  await send("Emulation.setDeviceMetricsOverride", {
    width: 1440,
    height: 1300,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await send("Page.navigate", { url: session.url });
  await until(() =>
    evaluate(
      "document.getElementById('message')?.textContent.includes('workspace is ready')",
    ),
  );
  await evaluate(
    "document.querySelector('[name=document]').value='browser-fixture';document.querySelector('[name=content]').value='<script>window.untrustedExecuted=true</script> Public browser test';document.getElementById('proposal-form').requestSubmit()",
  );
  await until(() =>
    evaluate(
      "document.querySelector('#items button')?.textContent==='Review change'",
    ),
  );
  await evaluate("document.querySelector('#items button').click()");
  await until(() => evaluate("document.getElementById('review').open"));
  if (
    !(await evaluate(
      "document.getElementById('approve').disabled && !window.untrustedExecuted && document.getElementById('review-content').textContent.includes('<script>')",
    ))
  )
    throw Error("Review isolation failed");
  const reviewPng = await send("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(
    path.join(out, "review.png"),
    Buffer.from(reviewPng.data, "base64"),
  );
  await evaluate(
    "document.getElementById('confirm').click();document.getElementById('approve').click()",
  );
  await until(() =>
    evaluate(
      "document.querySelector('#items button')?.textContent==='Execute approved action'",
    ),
  );
  await evaluate("document.querySelector('#items button').click()");
  await until(() =>
    evaluate(
      "document.querySelector('#items small')?.textContent.includes('Verified locally')",
    ),
  );
  await evaluate("document.querySelector('#items button').click()");
  await until(() =>
    evaluate(
      "!busy && document.getElementById('message').textContent.includes('did not create a second update')",
    ),
  );
  const status = await evaluate("api('status')");
  if (status.items[0].document_version !== 1)
    throw Error("Duplicate execution");
  await evaluate("document.getElementById('recovery-refresh').click()");
  await until(() =>
    evaluate(
      "!busy && document.querySelector('#recovery-items button')?.textContent==='Recover existing result'",
    ),
  );
  await evaluate("document.querySelector('#recovery-items button').click()");
  await until(() =>
    evaluate(
      "!busy && document.getElementById('message').textContent.includes('Existing result recovered')",
    ),
  );
  const recovery = await evaluate("api('recovery')");
  if (recovery.heads.receiver !== 1 || recovery.heads.witness !== 1)
    throw Error("Recovery duplicated an effect");
  const screenshot = await send("Page.captureScreenshot", {
    format: "png",
    captureBeyondViewport: true,
  });
  fs.writeFileSync(
    path.join(out, "app.png"),
    Buffer.from(screenshot.data, "base64"),
  );
  fs.writeFileSync(
    path.join(out, "result.json"),
    JSON.stringify(
      {
        passed: true,
        proposal_review_approval_execution_retry: true,
        untrusted_content_rendered_as_text: true,
        version_after_retry: 1,
        receipt_only_recovery: true,
        external_model_calls: 0,
      },
      null,
      2,
    ),
  );
  console.log(
    "Browser workflow passed: exact review, approval, execution, retry and text isolation.",
  );
} finally {
  if (ws) ws.close();
  if (chrome) chrome.kill();
  app.kill();
}
