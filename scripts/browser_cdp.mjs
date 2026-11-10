// A fresh, local, headless Chrome driven over the DevTools protocol, for the
// browser checks (ui_smoke.mjs, passkey_smoke.mjs). No external network.
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

export const delay = (ms) => new Promise((r) => setTimeout(r, ms));

export async function until(test, what = "UI condition", tries = 300) {
  for (let i = 0; i < tries; i++) {
    if (await test()) return;
    await delay(100);
  }
  throw Error(what + " timeout");
}

export async function startChrome(out) {
  const profile = path.join(out, "profile");
  const log = fs.openSync(path.join(out, "chrome.log"), "w");
  const chrome = spawn(
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
  await until(() => fs.existsSync(path.join(profile, "DevToolsActivePort")), "Chrome");
  const port = fs.readFileSync(path.join(profile, "DevToolsActivePort"), "utf8").split("\n")[0];
  const tabs = await (await fetch("http://127.0.0.1:" + port + "/json")).json();
  const ws = new WebSocket(tabs.find((t) => t.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  let next = 0;
  const pending = new Map();
  const listeners = new Map();
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id) {
      const p = pending.get(m.id);
      pending.delete(m.id);
      m.error ? p.reject(Error(m.error.message)) : p.resolve(m.result);
    } else if (listeners.has(m.method)) {
      listeners.get(m.method)(m.params);
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
  await send("Page.enable");
  await send("Emulation.setDeviceMetricsOverride", {
    width: 1440,
    height: 1300,
    deviceScaleFactor: 1,
    mobile: false,
  });
  const screenshot = async (file) => {
    const png = await send("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: true,
    });
    fs.writeFileSync(file, Buffer.from(png.data, "base64"));
  };
  const close = () => {
    ws.close();
    chrome.kill();
  };
  // The page's own API, for checks: GETs use the session cookie, POSTs also
  // send the CSRF token the session returns.
  const api = (p, body) =>
    evaluate(`(async () => {
      const options = { credentials: "same-origin", cache: "no-store" };
      if (${JSON.stringify(body !== undefined)}) {
        const s = await (await fetch("/api/session", options)).json();
        options.method = "POST";
        options.headers = { "Content-Type": "application/json", "X-OpenProof-CSRF": s.csrf };
        options.body = ${JSON.stringify(JSON.stringify(body ?? null))};
      }
      const r = await fetch("/api/" + ${JSON.stringify(p)}, options);
      return { status: r.status, body: await r.json() };
    })()`).then((r) => {
      if (r.status !== 200) throw Error(p + ": " + JSON.stringify(r.body));
      return r.body;
    });
  return {
    send,
    evaluate,
    api,
    screenshot,
    close,
    on: (method, fn) => listeners.set(method, fn),
  };
}
