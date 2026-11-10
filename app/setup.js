// The passkey set-up page: one registration ceremony, run once.
//
// It runs on the passkey's origin, like the review page, so it is trusted
// (docs/TCB.md): the passkey it registers is the one every later approval
// needs. No workspace code is loaded on this origin.
import { $, api, startSession, linkWorkspace, fromBase64url, toBase64url, busy } from "./common.js";

let workspace = "";

async function setup() {
  if (!window.PublicKeyCredential) throw Error("This browser does not support passkeys.");
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
  await api("passkey/register/finish", {
    credential_id: toBase64url(credential.rawId),
    client_data_json: toBase64url(response.clientDataJSON),
    authenticator_data: toBase64url(response.getAuthenticatorData()),
    public_key: toBase64url(response.getPublicKey()),
    algorithm: -7,
  });
  location.assign(workspace + "/#passkey");
}

$("setup").onclick = async () => {
  if (!(await busy($("setup"), setup))) $("setup").disabled = false;
};

startSession()
  .then((s) => {
    workspace = s.workspace;
    linkWorkspace(workspace);
    $("setup").disabled = false;
  })
  .catch((e) => {
    $("message").textContent = e.message;
    $("message").classList.remove("quiet");
  });
