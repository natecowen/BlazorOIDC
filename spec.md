# Blazor Server OIDC RBAC – Technical Specification

This is the **build specification** for the application. It defines what to implement and how it should behave.

For project goals and audience, see [readme.md](readme.md).
For design rationale and developer guidance, see [architecture.md](architecture.md).

---

## 1. Technology Stack

- **.NET 10 (LTS)**
- **Blazor Server**
- **Microsoft.AspNetCore.Authentication.OpenIdConnect**
- **Microsoft Authentication Builder**
- **Microsoft Authorization Framework**
- **Generic OpenID Connect provider**
  - Keycloak used as the reference implementation
- **Nunit for unit testing**
- **Serilog Asp.Net Core - Console Logging**

---

## 2. Authentication Model

The application uses **server-side authentication** with:

- OpenID Connect challenge/response
- Encrypted authentication cookies
- Claims-based authorization

**Tokens are never exposed to the browser.**

All authentication state lives:

- In the ASP.NET authentication cookie
- In server memory during request execution

The authentication cookie MUST be configured with:

- HttpOnly = true
- SecurePolicy = Always (except local HTTP dev)
- SameSite = Lax (or None with Secure for cross-site IdP redirects)
- IsEssential = true
- Cookie name must be application-specific (not default)

If token size causes cookie chunking, chunking MUST be enabled and tested.


### Authentication Observability

The application MUST:

- Log authentication failures at Warning level
- Log token refresh failures with reason (never token contents)
- Log forced re-authentication events
- Never log raw tokens, refresh tokens, or authorization codes

Recommended structured log fields:
- User ID (if known)
- Authentication scheme
- Failure reason
- Correlation ID

---

## 3. Authentication Flow

### 3.1 Login Flow

1. User requests a protected route
2. ASP.NET triggers an OIDC challenge
3. User is redirected to the Identity Provider (IdP)
4. User authenticates at the IdP
5. IdP redirects back with authorization code
6. Server exchanges code for tokens
7. Claims are extracted and normalized
8. Authentication cookie is issued

### 3.2 Logout Flow

1. User initiates logout
2. Local authentication cookie is invalidated
3. If the IdP end-session endpoint is configured, the user is redirected there; if not, this step is skipped silently
4. User is redirected to the home page

### 3.3 Token Refresh

Refresh tokens are stored **server-side only**, in the authentication properties within the encrypted cookie.

**Prerequisites:**

- The `offline_access` scope must be requested during OIDC login (this is what tells the IdP to issue a refresh token)
- `SaveTokens` must be enabled in the OIDC middleware configuration (this stores the tokens in the authentication properties so they're available later)

**Mechanism:**

1. `CookieAuthenticationEvents.OnValidatePrincipal` fires on each authenticated request
2. The handler checks whether the access token is expired or near expiry
3. If refresh is needed, the handler calls the IdP token endpoint with the stored refresh token
4. The handler **validates the new ID token** returned in the refresh response (issuer, signature, expiry) before accepting it
5. **On success:** the `ClaimsPrincipal` is replaced with claims from the validated token, new tokens replace the old tokens in the authentication properties, and the cookie is reissued
6. **On failure** (invalid_grant, token validation failure, network error, IdP unreachable): the principal is rejected via `context.RejectPrincipal()`, which forces re-authentication on the next request

**Constraints:**

- No user-visible interruption during successful refresh
- No retry logic — a single failed refresh attempt rejects the session
- Refresh must not extend the session beyond the 24-hour absolute lifetime
- Never trust a refresh response without validating the new ID token
- Token expiry checks MUST allow a configurable clock skew (default: 2 minutes); tokens nearing expiry within the skew window are refreshed proactively

### 3.4 Session Lifetime

- Sliding session expiration enabled
- Sliding window duration is **configurable** (default: 30 minutes)
- Absolute maximum session lifetime: **24 hours**
- After 24 hours, user must re-authenticate regardless of activity
- Token clock skew window: **configurable** (default: 2 minutes) — tokens within this window of expiry are treated as expired for refresh purposes

---

## 4. Identity Provider Configuration

### 4.1 Generic OIDC Requirements

The Identity Provider must support:

- Authorization Code Flow
- PKCE
- Refresh Tokens
- ID Token claims

Required endpoints:

- Authorization endpoint
- Token endpoint
- UserInfo endpoint (optional)
- End-session endpoint (optional)

### 4.2 Keycloak Reference Configuration

Keycloak is used as the concrete example:

- Confidential client
- Authorization Code Flow
- Roles and/or groups mapped into tokens
- Roles emitted into:
  - ID Token
  - Access Token

---

## 5. Claims and Role Mapping

### 5.1 Role Strategy

The application supports **configurable role sourcing**:

- ID Token claims
- Access Token claims

Supported role models:

- Flat roles
  - `View`
  - `Edit`
  - `Admin`

### 5.2 Configuration Model

Example configuration:

```json
{
  "Authorization": {
    "RoleClaimSource": "IdToken",
    "RoleClaimPath": "realm_access.roles"
  }
}
```

- `RoleClaimSource`: Which token to extract roles from (`IdToken` or `AccessToken`)
- `RoleClaimPath`: Dot-notation path to the roles array within the token. For Keycloak's default structure (`realm_access.roles`), the normalizer reads the `realm_access` claim, parses its JSON value, and extracts the `roles` array. For IdPs that emit a flat `roles` claim, use `"roles"` (no dot notation).

### 5.3 Claims Normalization

During sign-in:

1. Token claims are inspected
2. The claim specified by `RoleClaimPath` is located (handling nested JSON if the path contains a dot)
3. Role values are extracted from the claim (as a JSON array)
4. Each role is added as a standard `ClaimTypes.Role` claim on the `ClaimsPrincipal`

This occurs **once at authentication time**.

No token parsing occurs during normal request processing after login. (The token refresh mechanism in §3.3 does validate new tokens, but this is auth infrastructure — the application itself never parses tokens for authorization decisions.)

---

## 6. Authorization Design

### 6.1 Authorization Model

The application uses **Microsoft Authorization** with:

- Policy-based authorization (primary)
- Role-based authorization (secondary)

### 6.2 Roles

Defined roles:

- `View`
- `Edit`
- `Admin`

Role hierarchy (conceptual):

- Admin ⇒ Edit ⇒ View

Hierarchy is enforced via policies, not implicit role inheritance.

All role hierarchy rules MUST be defined in a single authorization policy registration section.
No page or component may implement role hierarchy logic directly.


### 6.3 Policies

| Policy | Required Roles | Description |
|--------|---------------|-------------|
| `CanView` | View, Edit, or Admin | Base-level access |
| `CanEdit` | Edit or Admin | Modification access |
| `IsAdmin` | Admin | Full administrative access |

### 6.4 Usage Patterns

Protected routes:

- `[Authorize(Policy = "CanEdit")]`

Component-level authorization:

- `<AuthorizeView Policy="IsAdmin">`

Role-based usage (supported but discouraged for scaling):

- `[Authorize(Roles = "Admin")]`

---

## 7. Pages and Routes

### 7.1 Page Inventory

| Route | Page | Authorization | Description |
|-------|------|--------------|-------------|
| `/` | Home | None (public) | Landing page, accessible to all users |
| `/protected` | Protected | `CanView` | Requires authentication and View role or higher |
| `/admin` | Admin | `IsAdmin` | Requires Admin role |
| `/claims` | Claims | `[Authorize]` (any authenticated user) | Displays the current user's claims (grouped summary + raw table) |
| `/dev-login` | Dev Login | None | **Development only.** Role picker for local development without an IdP. See §7.5 |
| `/access-denied` | Access Denied | None | Shown when an authenticated user lacks the required role |

### 7.2 Navigation Bar

The shared layout includes authentication-aware UI in the navigation bar:

- **Unauthenticated:** Login button
- **Authenticated:** Display username, current role, and a Logout button

### 7.3 Route Authorization

Routes are protected using:

- `AuthorizeRouteView`
- `[Authorize]` attributes

### 7.4 Unauthorized Access Behavior

- **Unauthenticated users** requesting a protected route trigger an authentication challenge:
  - **Production:** redirected to the IdP login page via OIDC challenge
  - **Development:** redirected to `/dev-login` (the auth challenge is configured to use `/dev-login` as the login path when `IsDevelopment()` is true)
- **Authenticated users without the required role** are redirected to the Access Denied page (`/access-denied`)

### 7.5 Development Login Bypass

For local development without a running IdP, the application provides a dev login page.

**Behavior:**

1. The `/dev-login` route is registered **only** when `IHostEnvironment.IsDevelopment()` returns true
2. The page presents a simple form where the developer selects a role (View, Edit, or Admin)
3. On submission, the application creates a `ClaimsPrincipal` with the selected role and issues an authentication cookie
4. The developer is redirected to the home page as an authenticated user

**Security constraints:**

- The dev login route, middleware, and all supporting code must be **completely excluded** from non-development builds
- Guard with `IHostEnvironment.IsDevelopment()` — do not use a configuration flag that could accidentally be enabled in production
- The dev login page should display a clear visual warning that it is a development-only feature

---

## 8. Configuration and Secrets Management

### 8.1 Configuration Structure

The application uses **separate configuration files** instead of appsettings.json:

```
BlazorOIDC/
  Configs/
    oidc.json          # OIDC provider settings (authority, client ID, scopes, callback paths)
    authorization.json # Role claim mapping, policy definitions
```

Each file is loaded explicitly via `ConfigurationBuilder.AddJsonFile()` in Program.cs.

### 8.2 Configuration Schemas

**oidc.json:**

```json
{
  "Oidc": {
    "Authority": "https://keycloak.example.com/realms/myrealm",
    "ClientId": "blazor-app",
    "Scopes": ["openid", "profile", "roles", "offline_access"],
    "CallbackPath": "/signin-oidc",
    "SignedOutCallbackPath": "/signout-callback-oidc"
  }
}
```

**authorization.json:**

```json
{
  "Authorization": {
    "RoleClaimSource": "IdToken",
    "RoleClaimPath": "realm_access.roles"
  },
  "Session": {
    "SlidingExpirationMinutes": 30,
    "AbsoluteExpirationHours": 24,
    "ClockSkewMinutes": 2
  }
}
```

### 8.3 Secrets Management

Secrets are **never stored in config files** or source control.

| Environment | Mechanism | Secrets |
|------------|-----------|---------|
| Development | `dotnet user-secrets` | ClientSecret |
| Production (Kubernetes) | Kubernetes Secrets mounted as environment variables | ClientSecret, any sensitive OIDC config |

Non-sensitive configuration in production is provided via Kubernetes ConfigMaps.

### 8.4 Loading Priority

Configuration sources are loaded in this order (last wins):

1. Config files (`Configs/*.json`)
2. User secrets (development only)
3. Environment variables (production)

### 8.5 Dependency Injection

All configuration is bound to strongly typed POCOs and injected via `IOptions<T>`.

---

## 9. Security Considerations

### 9.1 Secure Defaults

- HTTPS required
- Secure cookies
- HttpOnly cookies
- SameSite protection

### 9.2 CSRF and XSS

- Authentication cookies mitigate token theft
- No browser-accessible tokens exist

### 9.3 Session Expiration

- Silent refresh prevents user disruption
- Absolute expiration enforces re-authentication

---

## 10. Acceptance Criteria

Each criterion is a testable statement that defines "done" for a feature area.

### 10.1 Authentication — Login

- AC-1: When an unauthenticated user navigates to `/protected`, they are redirected to the IdP login page
- AC-2: When an unauthenticated user navigates to `/admin`, they are redirected to the IdP login page
- AC-3: After successful IdP authentication, the user is redirected back to the originally requested page
- AC-4: After successful authentication, an encrypted authentication cookie is present in the browser
- AC-5: After successful authentication, no tokens (access, ID, or refresh) are accessible in the browser

### 10.2 Authentication — Logout

- AC-6: When an authenticated user clicks Logout, the authentication cookie is removed
- AC-7: After logout, navigating to `/protected` redirects to the IdP login page
- AC-8: If the IdP end-session endpoint is configured, logout redirects through it before returning to the home page
- AC-9: If the IdP end-session endpoint is not configured, logout clears the cookie and redirects to the home page without error

### 10.3 Token Refresh

- AC-10: When an authenticated user makes a request and the access token is expired, the token is silently refreshed using the refresh token
- AC-11: After a successful token refresh, the user experiences no interruption or redirect
- AC-12: When the refresh token is invalid or revoked, the user is forced to re-authenticate on their next request
- AC-13: When the IdP is unreachable during a refresh attempt, the user is forced to re-authenticate
- AC-14: When the IdP returns an invalid ID token during a refresh (bad signature, wrong issuer, expired), the session is rejected and the user must re-authenticate
- AC-51: Token expiry checks use the configurable clock skew value (default: 2 minutes)
- AC-52: Tokens within the clock skew window of expiry are proactively refreshed before actual expiry

### 10.4 Session Lifetime

- AC-15: An idle session expires after the configured sliding window (default: 30 minutes), forcing re-authentication
- AC-16: An active session is forced to re-authenticate after 24 hours regardless of activity
- AC-17: Token refresh does not extend the session beyond the 24-hour absolute lifetime
- AC-18: The sliding window duration can be changed via `Session.SlidingExpirationMinutes` in authorization.json

### 10.5 Claims Normalization

- AC-19: Role claims from the configured token source are mapped to standard `ClaimTypes.Role` claims on the `ClaimsPrincipal`
- AC-20: The role claim source (`IdToken` or `AccessToken`) is configurable via `Authorization.RoleClaimSource`
- AC-21: The role claim path is configurable via `Authorization.RoleClaimPath` and supports dot-notation for nested JSON claims (e.g., `realm_access.roles`)
- AC-22: Claims normalization occurs once at authentication time; the application does not parse tokens for authorization decisions after login

### 10.6 Authorization Policies

- AC-23: A user with the `View` role can access pages protected by `CanView`
- AC-24: A user with the `View` role cannot access pages protected by `CanEdit` or `IsAdmin`
- AC-25: A user with the `Edit` role can access pages protected by `CanView` and `CanEdit`
- AC-26: A user with the `Edit` role cannot access pages protected by `IsAdmin`
- AC-27: A user with the `Admin` role can access pages protected by `CanView`, `CanEdit`, and `IsAdmin`

### 10.7 Route Protection

- AC-28: The home page (`/`) is accessible without authentication
- AC-29: The `/protected` page requires the `CanView` policy
- AC-30: The `/admin` page requires the `IsAdmin` policy
- AC-31: The `/claims` page requires authentication but no specific role
- AC-32: An authenticated user without the required role is redirected to `/access-denied`

### 10.8 Navigation Bar

- AC-33: When unauthenticated, the nav bar displays a Login button
- AC-34: When authenticated, the nav bar displays the username, current role, and a Logout button
- AC-35: Clicking the Login button initiates the login flow (OIDC challenge in production, redirect to `/dev-login` in development)
- AC-36: Clicking the Logout button initiates the logout flow

### 10.9 Claims Page

- AC-37: The `/claims` page displays a grouped summary with sections for Identity (name, email), Roles, and Token metadata (issuer, expiry)
- AC-38: The `/claims` page displays a raw claims table showing every claim type and value on the current `ClaimsPrincipal`
- AC-39: The `/claims` page is not accessible to unauthenticated users

### 10.10 Development Login Bypass

- AC-40: When `IHostEnvironment.IsDevelopment()` is true, the `/dev-login` route exists and is accessible
- AC-41: When `IHostEnvironment.IsDevelopment()` is false, the `/dev-login` route does not exist (returns 404)
- AC-42: The dev login page presents a form to select a role (View, Edit, or Admin)
- AC-43: Submitting the dev login form creates an authenticated session with the selected role
- AC-44: The dev login page displays a visible warning that it is a development-only feature
- AC-45: In development mode, unauthenticated users requesting a protected route are redirected to `/dev-login`

### 10.11 Configuration

- AC-46: The application loads OIDC settings from `Configs/oidc.json`
- AC-47: The application loads authorization settings from `Configs/authorization.json`
- AC-48: Secrets set via `dotnet user-secrets` override values from config files
- AC-49: Environment variables override all other configuration sources
- AC-50: The `ClientSecret` is never present in any config file committed to source control

### 10.12 Cookie Configuration

- AC-53: The authentication cookie has `HttpOnly = true`
- AC-54: The authentication cookie uses `SecurePolicy = Always` (except local HTTP development)
- AC-55: The authentication cookie has `SameSite = Lax`
- AC-56: The authentication cookie is marked as essential (`IsEssential = true`)
- AC-57: The authentication cookie has an application-specific name (not the framework default)
- AC-58: If token size causes cookie chunking, chunking is enabled and functional

### 10.13 Authentication Observability

- AC-59: Authentication failures are logged at Warning level
- AC-60: Token refresh failures are logged with reason but never with token contents
- AC-61: Forced re-authentication events are logged
- AC-62: Raw tokens, refresh tokens, and authorization codes never appear in log output

### 10.14 Testing

- AC-63: Unit tests exist covering claims normalization, authorization policy evaluation, and token refresh logic
- AC-64: All unit tests pass

---

## 11. Implementation Order

Each phase produces a working application state. Acceptance criteria (AC) that can be verified after each phase are listed.

### Phase 1: Configuration Foundation

- Create `Configs/oidc.json` and `Configs/authorization.json` with schemas from §8.2
- Create strongly typed POCOs for each config section
- Load config files in Program.cs via `ConfigurationBuilder.AddJsonFile()`
- Register POCOs with `IOptions<T>` in DI
- Configure user secrets for `ClientSecret`
- Configure Serilog with console sink in Program.cs
- Create NUnit test project (`BlazorOIDC.Tests`) and add to solution

**Verifiable:** AC-46, AC-47, AC-48, AC-49, AC-50

### Phase 2: Cookie Authentication & Dev Login Bypass

- Register cookie authentication scheme in Program.cs (no OIDC yet)
- Create the `/dev-login` page with role picker (View, Edit, Admin), gated by `IsDevelopment()`
- On form submission, create a `ClaimsPrincipal` with the selected role as a `ClaimTypes.Role` claim and issue a cookie
- Add development-only warning banner to the dev login page
- Configure authentication cookie: HttpOnly, SecurePolicy, SameSite=Lax, IsEssential, application-specific name
- Enable cookie chunking for large token payloads

**Verifiable:** AC-40, AC-41, AC-42, AC-43, AC-44, AC-45, AC-53, AC-54, AC-55, AC-56, AC-57, AC-58

### Phase 3: Authorization Policies

- Register policies in Program.cs: `CanView`, `CanEdit`, `IsAdmin`
- Each policy evaluates `ClaimTypes.Role` membership per the table in §6.3

**Verifiable:** AC-23, AC-24, AC-25, AC-26, AC-27 (using dev login to create sessions with different roles)

### Phase 4: Pages & Route Protection

- Add `AuthorizeRouteView` to Routes.razor
- Create the `/protected` page with `[Authorize(Policy = "CanView")]`
- Create the `/admin` page with `[Authorize(Policy = "IsAdmin")]`
- Create the `/access-denied` page
- Configure the app to redirect unauthorized users to `/access-denied`

**Verifiable:** AC-28, AC-29, AC-30, AC-32 (using dev login to test each route with different roles)

### Phase 5: Navigation Bar

- Update the shared layout to include auth-aware UI
- Unauthenticated: show Login button
- Authenticated: show username, role, and Logout button
- Wire Login button to trigger authentication challenge
- Wire Logout button to clear the authentication cookie and redirect to home

**Verifiable:** AC-33, AC-34, AC-35, AC-36, AC-6, AC-7

### Phase 6: Claims Page

- Create the `/claims` page with `[Authorize]`
- Grouped summary section: Identity (name, email), Roles, Token metadata (issuer, expiry)
- Raw claims table: every claim type and value from the `ClaimsPrincipal`

**Verifiable:** AC-37, AC-38, AC-39, AC-31

### Phase 7: Claims Normalization

- Implement the `OnTokenValidated` event handler
- Read `RoleClaimSource` and `RoleClaimPath` from `Authorization` config
- Parse the claim at `RoleClaimPath`, handling nested JSON (dot notation) for Keycloak's `realm_access.roles` structure
- Map each extracted role to a standard `ClaimTypes.Role` claim on the `ClaimsPrincipal`

**Verifiable:** AC-19, AC-20, AC-21, AC-22

### Phase 8: OIDC Authentication

- Register OpenID Connect authentication in Program.cs
- Configure Authority, ClientId, ClientSecret, Scopes, CallbackPath from `Oidc` config + secrets
- Enable Authorization Code Flow with PKCE
- Enable `SaveTokens = true` so tokens are stored in authentication properties for later refresh
- Scopes must include `offline_access` to receive a refresh token from the IdP
- Wire the claims normalization handler from Phase 7 into the OIDC events
- Unauthenticated users requesting protected routes trigger an OIDC challenge
- Log authentication failures at Warning level (never raw tokens)

**Verifiable:** AC-1, AC-2, AC-3, AC-4, AC-5, AC-59

### Phase 9: Token Refresh & Session Lifetime

- Store tokens in authentication properties within the cookie
- Implement `OnValidatePrincipal` handler: check token expiry, refresh via token endpoint, reject on failure
- Configure sliding expiration from `Session.SlidingExpirationMinutes`
- Configure absolute expiration from `Session.AbsoluteExpirationHours`
- Ensure refresh does not extend past the absolute lifetime
- Use `ClockSkewMinutes` for proactive token refresh within the skew window
- Log token refresh failures with reason and forced re-auth events (never token contents)

**Verifiable:** AC-10, AC-11, AC-12, AC-13, AC-14, AC-15, AC-16, AC-17, AC-18, AC-51, AC-52, AC-60, AC-61, AC-62

### Phase 10: Logout Flow

- Wire logout to clear the local authentication cookie
- If the IdP end-session endpoint is configured, redirect through it
- If not configured, redirect directly to home
- Verify logout works with both the dev login bypass and real OIDC

**Verifiable:** AC-6, AC-7, AC-8, AC-9

### Phase 11: Unit Testing

- Create unit tests for claims normalization (flat and nested role paths)
- Create unit tests for authorization policy evaluation (role hierarchy)
- Create unit tests for token refresh logic (expiry check, clock skew, failure handling)

**Verifiable:** AC-63, AC-64

---

## 12. Summary

This specification defines the implementation requirements for a Blazor Server OIDC authentication and RBAC system.

This document serves as the authoritative reference for implementation. For design rationale, see [architecture.md](architecture.md).
