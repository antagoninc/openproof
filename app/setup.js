// The passkey set-up page: one registration ceremony, run once.
//
// It runs on the passkey's origin, like the review page, so it is trusted
// (docs/TCB.md): the passkey it registers is the one every later approval
// needs. No workspace code is loaded on this origin.
import { $, api, startSession, linkWorkspace, fromBase64url, toBase64url, busy, passkeyCode } from "./common.js";

let workspace = "";

/** One registration ceremony; returns what the owner app checks. */
async function register(begin) {
  if (!window.PublicKeyCredential) throw Error("This browser does not support passkeys.");
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
  return {
    credential_id: toBase64url(credential.rawId),
    client_data_json: toBase64url(response.clientDataJSON),
    authenticator_data: toBase64url(response.getAuthenticatorData()),
    public_key: toBase64url(response.getPublicKey()),
    algorithm: -7,
  };
}

async function setup() {
  const made = await register(await api("passkey/register/begin", {}));
  await api("passkey/register/finish", made);
  location.assign(workspace + "/#passkey");
}

// The new passkey takes effect only when the administrator types the code
// that this page shows (docs/PASSKEY.md). The page computes the code from the
// key that it made and from its own address. The owner app chooses neither
// the code nor the command that the page shows for the administrator.
async function replace() {
  const made = await register(await api("passkey/replace/begin", {}));
  const code = await passkeyCode(made.public_key, location.hostname, location.origin);
  await api("passkey/replace/prepare", made);
  $("code").textContent = code;
  $("confirm").hidden = false;
  $("replace").hidden = true;
  $("complete").hidden = false;
}

async function complete() {
  const done = await api("passkey/replace/complete", {});
  if (done.status !== "replaced")
    throw Error("The receiver does not have the replacement yet. The administrator must run the command first.");
  location.assign(workspace + "/#passkey");
}

for (const [id, action] of [["setup", setup], ["replace", replace], ["complete", complete]])
  $(id).onclick = async () => {
    if (!(await busy($(id), action))) $(id).disabled = false;
  };

startSession()
  .then((s) => {
    workspace = s.workspace;
    linkWorkspace(workspace);
    // The owner app says which of the two the home needs. It decides nothing:
    // the receiver refuses a second set-up and a replacement without the administrator.
    $(s.passkey ? "again" : "first").hidden = false;
    $("setup").disabled = false;
    $("replace").disabled = !s.roles;
    $("no-roles").hidden = s.roles;
  })
  .catch((e) => {
    $("message").textContent = e.message;
    $("message").classList.remove("quiet");
  });
