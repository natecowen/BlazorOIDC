# Architecture Decisions & Developer Guidance

This document explains the **design rationale** behind key architectural choices in the Blazor OIDC project. It is intended for developers who want to understand *why* the application is built this way.

For *what to build*, see [spec.md](spec.md).
For *how to get started*, see [readme.md](readme.md).

---

## Terminology

- Authentication: Who the user is
- Authorization: What the user can do
- Claim: A statement about a user
- Role: A specific type of claim used for authorization
- Policy: A named authorization rule


---

## Threat Model (Simplified)

This application explicitly defends against:

- Token theft via XSS
- Token leakage via browser storage
- Session fixation
- Unauthorized route access
- Role escalation via client-side manipulation

This application does NOT defend against:

- Compromised Identity Provider
- Malicious server operators
- Network-level MITM attacks without HTTPS
- Authorization bypass in downstream APIs (out of scope)

These constraints are intentional and aligned with Blazor Server’s execution model.

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

---

## Design Approach - Explaining App Parts

This section goes over specific files in the app and explains their purpose. 

### TokenRefreshService

This application introduces an explicit **TokenRefreshService** that runs during cookie validation.

Its responsibilities are:

- Inspect the access token expiration
- Apply a configurable clock-skew tolerance
- Refresh the access token using the refresh token when necessary
- Update the authentication cookie *in-place*
- Fail safely by rejecting the session if refresh is not possible


### ClaimsNormalizationService

 Different identity providers (and even different configurations of the same provider) emit roles and groups in different ways. This application introduces a **ClaimsNormalizationService** that acts as a translation layer between the identity provider claim formats and the ASP.NET Core authorization expectations. 

 Ultimately, it allows for greater flexibility via configs without hardcoding specific IDP items inside the app. 


The service:
- Extracts roles from a configurable token source (ID token or access token)
- Supports nested JSON using dot-notation paths
- Normalizes extracted roles into `ClaimTypes.Role`
- Runs during login and after token refresh


### DevLoginComponent

 This controller provides a DEVELOPMENT-ONLY authentication bypass
 that simulates a logged-in user with a specific role.

- Issues a local authentication cookie
- Allows selecting a role (View, Edit, Admin)
- Never issues or simulates OIDC tokens
- Is strictly gated to development environments

This enables rapid testing of authorization logic without weakening production security.

#### OIDC Toggle for Development (`ShouldLocalDevUseOIDC`)

By default (`false`), development mode uses the dev-login bypass for rapid iteration without an IdP. When set to `true` in `oidc.json`, the full OIDC flow is used in development, enabling end-to-end testing against a local IdP (e.g., Keycloak in Docker). This toggle only affects which login path is used in development — it has no effect in production, where OIDC is always used.

#### Safety Guarantees

The development login:
- Is disabled outside of development environments
- Does not mimic or replace real OIDC behavior
- Exists solely to support RBAC testing during development
- `ShouldLocalDevUseOIDC` is a development convenience toggle, not a security gate — the `IsDevelopment()` guard remains the only control for dev-login availability

It must never be enabled in production deployments.