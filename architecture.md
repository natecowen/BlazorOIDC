# Architecture Decisions & Developer Guidance

This document explains the **design rationale** behind key architectural choices in the Blazor OIDC project. It is intended for developers who want to understand *why* the application is built this way.

For *what to build*, see [spec.md](spec.md).
For *how to get started*, see [readme.md](readme.md).

---

## Why Cookies, Not Tokens

Blazor Server executes UI logic on the server.

Therefore:

- Tokens are unnecessary for UI authorization
- Cookies provide stronger CSRF and XSS protection
- No token persistence is required client-side

Tokens exist only to:

- Validate identity at login
- Retrieve claims
- Refresh sessions silently

After authentication, the application relies entirely on the encrypted authentication cookie. Tokens are never sent to or stored in the browser.

---

## Server-Side Safety

This RBAC model is safe because:

- UI executes server-side
- APIs are not externally accessible
- Users never receive tokens

All authorization checks happen on the server. The browser only receives rendered HTML over the SignalR connection.

---

## Explicit Warning

This authentication model **must not** be copied to:

- Blazor WebAssembly
- Public APIs
- Client-side SPAs

Without additional API-level authorization. In those contexts, tokens must be validated on every request and the client cannot be trusted.

---

## Common Pitfalls

- **Treating Blazor Server like Blazor WASM** — Server-side auth and client-side auth have fundamentally different security models
- **Exposing tokens to the browser** — Blazor Server has no reason to do this; if tokens reach the client, something is misconfigured
- **Hardcoding role claim names** — Different IdPs use different claim types; always make the role claim source configurable
- **Using roles instead of policies everywhere** — Policies scale better; `[Authorize(Policy = "CanEdit")]` is more maintainable than `[Authorize(Roles = "Edit,Admin")]`
