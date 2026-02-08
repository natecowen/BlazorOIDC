# Blazor OIDC

A Blazor Server application implementing OAuth 2.0 / OpenID Connect authentication with role-based access control (RBAC).

## Purpose and Goals

This application serves as:

- A **learning tool** for developers new to modern authentication
- A **production-ready starter template**
- A **reference implementation** for Blazor Server authentication using Microsoft-supported libraries

Primary goals:

- Standards-compliant OIDC authentication
- Server-side session security (no browser token storage)
- Configurable role and group mapping
- Role-based route and component protection
- Silent token refresh with forced re-authentication every 24 hours
- Clear documentation and extensibility

Non-goals:

- Client-side (WASM) authentication
- API authorization enforcement (out of scope for v1)
- Custom identity provider logic

## Target Audience

This project targets **mid-level developers**, particularly those transitioning from legacy or monolithic systems to:

- Modern .NET
- Claims-based identity
- OAuth 2.0 / OIDC concepts

Assumptions:

- Comfortable with C# and ASP.NET
- Limited prior exposure to OAuth/OIDC internals
- Familiar with role-based authorization concepts

## Prerequisites

- Install VS Code and C# Dev Kit Extension
- Install .NET SDK (.NET 10)
- Install Claude Code and setup with VS Code

## Build & Run

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

Development URLs:

- HTTPS: https://localhost:7064
- HTTP: http://localhost:5132

## Extensibility

The application is intentionally minimal — a public landing page, a protected page, and an admin page. This keeps the starter template focused on authentication plumbing rather than application logic.

Designed extension points:

- **Additional pages and routes** — Add new pages with `[Authorize(Policy = "...")]` to demonstrate more granular access levels
- **Additional role sources** — Extend claims normalization to pull roles from access tokens, UserInfo endpoint, or external databases
- **Claims-based policies** — Create policies that evaluate arbitrary claims, not just roles (e.g., department, subscription tier)
- **API authorization** — Add API controllers with token-based auth for external consumers (see [architecture.md](architecture.md) for why this requires a different model)
- **External authorization handlers** — Plug in custom `IAuthorizationHandler` implementations for complex business rules

## Project Documents

- [spec.md](spec.md) — Technical specification (what to build)
- [architecture.md](architecture.md) — Design rationale and developer guidance (why it's built this way)
- [CLAUDE.md](CLAUDE.md) — AI coding agent instructions

---

## How This Project Was Built

This application was built with the dotnet CLI and Claude Code, using a spec-driven development approach.

<details>
<summary>Prompt used to generate the initial specification</summary>

```md
I'm building a Blazor Web App using Blazor Server.

This application will be used as a learning tool and starting template for implementing Oauth2.0 OIDC connect RBAC. The goal is to build a full featured app that can handle login, logout, token handling, token refresh, and role based access within the application. Certain routes will be protected with roles.

In detail, users should be able to use OIDC for application sign-on. Authenticated users with certain roles should be able to access certain pages. Example roles for this project are:
- View
- Edit
- Admin

This application should utilize the following:

- Microsoft.AspNetCore.Authentication.OpenIdConnect nuget package
- Microsoft Authentication Builder
- Microsoft Authorization

This application should be documented on how to use and setup this functionality step by step for end-users. It will be a teaching tool for others to add authentication to their application in a production ready manner.

Do you need more information to create me a technical specification document which I can use as a foundation to then build this application?
```

</details>

---

## See Code Coverage - WIP. 

- Add coverlet to the test project: `dotnet add package coverlet.collector` 
- Run test and collect coverage: `dotnet test --collect:"XPlat Code Coverage"`
- Run the report generator: `reportgenerator -reports:./TestResults/{guid}/coverage.cobertura.xml -targetdir:TestResults -reporttypes:Html`

> You may need to install the report generator with `dotnet tool install --global dotnet-reportgenerator-globaltool --version 5.5.1` and then add the dotnet tools to your path. For a MAC, run `export PATH=$PATH:$HOME/.dotnet/tools` and then `source ~/.zshrc`



---
## Helpful Links

- [Blazor Security Overview](https://learn.microsoft.com/en-us/aspnet/core/blazor/security/?view=aspnetcore-10.0&tabs=visual-studio)
  - Good to know items from that page: 
    - AuthorizeRouteView - Combines the behaviors of AuthorizeView and RouteView, so that it displays the page matching the specified route but only if the user is authorized to see it.
    - AuthorizeView - Selectively display UI depending on whether the user is authorized. 
    - Role-based and policy-based authorization
- [OAuth 2.0 Playground will help you understand the OAuth authorization flows](https://www.oauth.com/playground/)