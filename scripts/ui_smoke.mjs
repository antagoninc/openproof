// Browser-level workflow check in a fresh local Chrome profile, without a
// passkey: propose, review on the separate review page, approve, execute,
// retry. No external network or production owner home is used.
//   OPENPROOF_CHROME=/path/to/chrome node scripts/ui_smoke.mjs OUT_DIR
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { startChrome, until } from "./browser_cdp.mjs";

const out = path.resolve(process.argv[2]);
fs.mkdirSync(out, { recursive: false, mode: 0o700 });
const root = path.resolve(import.meta.dirname, "..");
const appLog = fs.openSync(path.join(out, "app.log"), "w");
const app = spawn(
  path.join(root, "target/debug/openproof-witness"),
  ["owner-app", "--home", path.join(out, "home"), "--session-file", path.join(out, "session.json")],
  { cwd: root, stdio: ["ignore", appLog, appLog] },
);
let b;
try {
  await until(() => fs.existsSync(path.join(out, "session.json")), "owner app start");
  const session = JSON.parse(fs.readFileSync(path.join(out, "session.json")));
  b = await startChrome(out);
  const { evaluate, send, api } = b;
  const message = () => evaluate("document.getElementById('message')?.textContent ?? ''");
  await send("Page.navigate", { url: session.url });
  await until(async () => (await message()).includes("workspace is ready"), "workspace");
  // The workspace ignores clicks while an operation runs, start-up included.
  const idle = () => until(() => evaluate("document.body.dataset.state === 'idle'"), "idle");
  await idle();

  // 1. Propose. Untrusted text must render as text on the review page.
  const content = "<script>window.untrustedExecuted=true</script> Public browser test";
  await evaluate(
    "document.querySelector('[name=document]').value='browser-fixture';" +
      `document.querySelector('[name=content]').value=${JSON.stringify(content)};` +
      "document.getElementById('proposal-form').requestSubmit()",
  );
  await until(
    () =>
      evaluate(
        "location.pathname==='/review' && document.getElementById('review')?.hidden === false",
      ),
    "review page",
  );
  const review = await evaluate(`({
    approveDisabled: document.getElementById('approve').disabled,
    executed: window.untrustedExecuted === true,
    content: document.getElementById('review-content').textContent,
    digest: document.getElementById('review-digest').textContent,
    scripts: performance.getEntriesByType('resource').map((e) => new URL(e.name).pathname)
      .filter((p) => p.endsWith('.js')).sort(),
    styles: [...document.styleSheets].map((s) => new URL(s.href).pathname),
  })`);
  const sha = crypto.createHash("sha256").update(content).digest("hex");
  if (
    !review.approveDisabled ||
    review.executed ||
    review.content !== content ||
    review.digest !== sha
  )
    throw Error("Review page did not show the exact text safely: " + JSON.stringify(review));
  // The review page runs only its own code and the two shared modules.
  if (JSON.stringify(review.scripts) !== JSON.stringify(["/approval.js", "/common.js", "/review.js"]))
    throw Error("Review page loaded other scripts: " + review.scripts);
  if (JSON.stringify(review.styles) !== JSON.stringify(["/base.css"]))
    throw Error("Review page loaded other styles: " + review.styles);
  await b.screenshot(path.join(out, "review.png"));

  // 2. Approve (no passkey in this home), back on the workspace.
  await evaluate(
    "document.getElementById('confirm').click();document.getElementById('approve').click()",
  );
  await until(
    async () => (await evaluate("location.pathname")) === "/" && (await message()).includes("Approved."),
    "approval",
  );
  await idle();
  const row = "[...document.querySelectorAll('.item')].find((r) => r.textContent.includes('browser-fixture'))";
  await until(
    () => evaluate(row + "?.querySelector('button')?.textContent==='Execute approved action'"),
    "execute button",
  );

  // 3. Execute, then retry the same action: no second update.
  await evaluate(row + ".querySelector('button').click()");
  await until(async () => (await api("status")).items[0]?.stage === "Verified locally", "execution");
  await until(() => evaluate(row + "?.querySelector('button')?.textContent==='Recover / refresh'"), "refresh button");
  await idle();
  await evaluate(row + ".querySelector('button').click()");
  await idle();
  if (!(await message()).includes("Retrying never creates a second update"))
    throw Error("Retry was not confirmed: " + (await message()));
  const status = await api("status");
  if (status.items.length !== 1 || status.items[0].document_version !== 1)
    throw Error("Duplicate execution: " + JSON.stringify(status.items));
  const recovery = await api("recovery");
  if (recovery.heads.receiver !== 1 || recovery.heads.witness !== 1)
    throw Error("Unexpected history: " + JSON.stringify(recovery.heads));
  // 4. The proposal form starts with no document name. For a document that
  // exists, it loads the current text and version; for a new name it is empty.
  await evaluate("document.getElementById('new-change').click()");
  const form = await evaluate(`({
    name: document.querySelector('[name=document]').value,
    known: [...document.querySelectorAll('#known-documents option')].map((o) => o.value),
  })`);
  if (form.name !== "" || !form.known.includes("browser-fixture"))
    throw Error("Unexpected proposal form: " + JSON.stringify(form));
  const choose = (name) =>
    evaluate(`(() => {
      const field = document.querySelector('[name=document]');
      field.value = ${JSON.stringify(name)};
      field.dispatchEvent(new Event('change'));
    })()`);
  const formState = () =>
    evaluate(`({
      text: document.querySelector('[name=content]').value,
      version: document.querySelector('[name=expected_version]').value,
      hint: document.getElementById('version-hint').textContent,
    })`);
  await choose("browser-fixture");
  await until(async () => {
    const f = await formState();
    return f.text === content && f.version === "1" && f.hint.includes("current text");
  }, "current text in the form");
  await choose("another-document");
  await until(async () => {
    const f = await formState();
    return f.text === "" && f.version === "0" && f.hint.includes("New document");
  }, "empty form for a new document");
  await evaluate("document.getElementById('compose').close()");
  await b.screenshot(path.join(out, "app.png"));
  fs.writeFileSync(
    path.join(out, "result.json"),
    JSON.stringify(
      {
        passed: true,
        review_on_separate_page: true,
        review_page_scripts: review.scripts,
        untrusted_content_rendered_as_text: true,
        form_loads_current_text: true,
        version_after_retry: 1,
        external_model_calls: 0,
      },
      null,
      2,
    ),
  );
  console.log("Browser workflow passed: separate review page, approval, execution, retry, text isolation, proposal form.");
} finally {
  if (b) b.close();
  app.kill();
}
