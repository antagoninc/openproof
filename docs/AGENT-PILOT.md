# Local agent pilot

Run `python3 scripts/agent_pilot.py outputs/my-agent-pilot` after a debug build, using a new directory. Python cryptography is required.

The supervisor creates ephemeral root, authority, actor and executor keys. It authorizes a bounded report artifact and launches examples/agent/worker.py as a separate process. That deterministic agent constructs a report and signs its action claim using only its actor seed. It receives no authority/root/executor seed in its input. The supervisor sends the result through the actual Rust execute-trusted command.

The pilot checks denied scope with no nonce consumption, approved execution, duplicate rejection, current trust verification, matching artifact bytes, installed revocation and rejection of an older snapshot. Executor seed files are created 0600 and removed in a finally block. No proprietary models, production credentials or external APIs are used.

This is a functioning deterministic agent integration, not an LLM-powered demo. It exercises the agent/tool boundary without a model provider. The agent process runs under the same OS account: process separation and selective key passing do not establish sandbox isolation against a malicious same-user process. A later untrusted-agent deployment needs an OS boundary or separate service with independently protected keys and storage.
