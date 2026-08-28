// Onyx gateway policy for the Obot filter example.
//
// The receiver maps each intercepted MCP tools/call onto a Cedar request:
//   principal = Agent::"obot"            (the --agent identity)
//   action    = Action::"<tool name>"    (e.g. Action::"read_file")
//   resource  = Tool::"<tool name>", carrying the call's arguments as
//               attributes (resource.path, resource.query, ...)
//
// ALLOWLIST style: nothing runs unless a permit matches, so an unknown tool —
// or a call missing a required argument — is denied by default (fail-closed).

entity Agent::"obot" {} ;

// Searching is harmless — always permitted.
permit(principal, action == Action::"search", resource);

// File reads are permitted ONLY inside the public tree.
permit(principal, action == Action::"read_file", resource)
  when { resource.path like "/data/public/*" };
