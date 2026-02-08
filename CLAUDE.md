# CLAUDE.md — Blazor OIDC Project

## Project Overview

Blazor Server application implementing OAuth 2.0 / OpenID Connect authentication with role-based access control (RBAC). Serves as both a learning tool and production-ready starter template.

See `spec.md` for the build specification (what to implement).
See `architecture.md` for design rationale (why it's built this way).
See `readme.md` for project overview and setup prerequisites.

Keep your replies extremely concise and focus on conveying the key information. No unnecessary fluff, no long code snippets. 

## Tech Stack

- .NET 10 (LTS), Blazor Server
- Microsoft.AspNetCore.Authentication.OpenIdConnect
- Microsoft Authentication Builder & Authorization Framework
- Generic OIDC provider (Keycloak as reference implementation)
- NUnit for unit testing
- Serilog (ASP.NET Core console sink)

## Project Structure

```
Blazor-OIDC/
├── BlazorOIDC/                  # Main application
│   ├── Program.cs               # App entry point, service configuration
│   ├── BlazorOIDC.csproj        # Project file (.NET 10)
│   ├── Components/
│   │   ├── App.razor            # Root component
│   │   ├── Routes.razor         # Routing
│   │   ├── _Imports.razor       # Global usings
│   │   ├── Layout/              # MainLayout, NavMenu, ReconnectModal
│   │   └── Pages/               # Home, Protected, Admin, Claims, DevLogin, AccessDenied
│   ├── Controllers/             # API endpoints (Auth, DevLogin)
│   ├── Models/                  # Configuration models (AuthorizationConfig, OidcOptions, SessionConfig)
│   ├── Services/                # Business logic services (ClaimsNormalizationService, TokenRefreshService)
│   ├── Configs/                 # JSON configuration files (oidc.json, authorization.json)
│   ├── Properties/
│   │   └── launchSettings.json  # Dev: https://localhost:7064
│   └── wwwroot/                 # Static assets (Bootstrap, CSS)
├── BlazorOIDC.Tests/            # Unit tests (NUnit with Moq)
│   ├── BlazorOIDC.Tests.csproj
│   ├── AuthControllerTests.cs
│   ├── AuthorizationPolicyTests.cs
│   ├── ClaimsNormalizationTests.cs
│   ├── ConfigurationTests.cs
│   ├── DevLoginControllerTests.cs
│   └── TokenRefreshTests.cs
├── BlazorOIDC.slnx              # Solution file
├── spec.md                      # Build specification (what to implement)
├── architecture.md              # Design rationale (why)
└── readme.md                    # Project overview & setup
```

## Build & Run Commands

```bash
# Restore dependencies
dotnet restore BlazorOIDC/BlazorOIDC.csproj

# Build
dotnet build BlazorOIDC/BlazorOIDC.csproj

# Run (development)
dotnet run --project BlazorOIDC/BlazorOIDC.csproj

# Run with HTTPS profile
dotnet run --project BlazorOIDC/BlazorOIDC.csproj --launch-profile https
```

## Development URLs

- HTTPS: https://localhost:7064
- HTTP: http://localhost:5132

## Architecture Decisions

- **Server-side auth only** — tokens never exposed to browser
- **Cookie-based sessions** — no client-side token storage
- **Policy-based authorization** preferred over role-based (`[Authorize(Policy = "CanEdit")]`)
- **Roles**: View, Edit, Admin (hierarchy: Admin > Edit > View, enforced via policies)
- **Claims normalization** happens once at authentication time
- **Silent token refresh** with 24-hour absolute session lifetime

## Folder Organization

- **Models/** — Configuration and data transfer objects (e.g., `AuthorizationConfig`, `OidcOptions`, `SessionConfig`)
  - All configuration classes that are bound to strongly-typed POCOs via `IOptions<T>`
  - Use this folder for any models that represent structured configuration or cross-cutting concerns
- **Controllers/** — API endpoints and request handlers (traditional ASP.NET controller pattern)
  - Use for HTTP endpoints that are not Razor components
- **Services/** — Business logic and integration services (e.g., `ClaimsNormalizationService`, `TokenRefreshService`)
  - Stateless services registered in DI for cross-cutting concerns
- **Components/** — Blazor components (pages and layout components)
- **Configs/** — JSON configuration files (oidc.json, authorization.json)

## Security Rules

- NEVER commit secrets (client IDs, secrets, keys) to source control
- Use `dotnet user-secrets` for development secrets
- Environment variables for production secrets
- HTTPS required
- Secure, HttpOnly, SameSite cookies

## Implementation Order (from spec)

1. OIDC authentication
2. Cookie configuration
3. Claims normalization
4. Authorization policies
5. Route protection
6. UI authorization

## Coding Conventions

- Use strongly typed configuration (IOptions<T> pattern)
- Prefer policy-based auth over raw role checks
- Follow .NET/Blazor naming conventions (PascalCase for public, camelCase for private)
- Keep authentication logic in Program.cs service configuration
