# Gabriel MCP gateway

Gabriel can connect to external Model Context Protocol (MCP) servers as bounded,
read-only context sources for specialist investigations. This is intentionally not
a general-purpose MCP client and does not expose arbitrary tool execution.

## Safety contract

- Endpoints must be HTTPS, include an explicit path, and cannot contain credentials,
  query strings, fragments, redirects, or proxy-forwarding metadata.
- Bearer credentials are encrypted at rest with the existing provider key ring and
  are never displayed in the workbench or returned by an API.
- A server is usable only after an initialize/tools-list handshake succeeds.
- Only tools with an explicit `readOnlyHint=true` annotation are admitted. Tool
  names and descriptions containing action/destructive terms are rejected.
- Calls are role-scoped, bounded to small requests and results, and sensitive keys
  (tokens, cookies, authorization values, secrets and private keys) are removed.
- Every registration, manifest refresh, revocation and completed read is audited.
- A failed or incomplete handshake is reported as degraded; it is never treated as
  healthy coverage.

The initial UI is for administrator-controlled registration and manifest refresh.
Specialist execution should use the gateway's typed `read()` boundary, not direct
network access or arbitrary remote tool names. Offensive, write-capable, or action
MCP servers must not be connected to production Gabriel.
