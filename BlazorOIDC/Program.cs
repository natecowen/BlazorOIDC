using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using BlazorOIDC.Components;
using BlazorOIDC.Models;
using BlazorOIDC.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Serilog;

// Bootstrap Serilog early for startup logging
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting Blazor OIDC application");

    var builder = WebApplication.CreateBuilder(args);

    // Fix configuration loading order (spec §8.4):
    // Clear defaults, then add sources lowest-to-highest priority.
    // Last source wins, so: JSON files < user secrets < env vars.
    builder.Configuration.Sources.Clear();
    builder.Configuration
        .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
        .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
        .AddJsonFile("Configs/oidc.json", optional: false, reloadOnChange: true)
        .AddJsonFile("Configs/authorization.json", optional: false, reloadOnChange: true);

    if (builder.Environment.IsDevelopment())
    {
        builder.Configuration.AddUserSecrets<Program>();
    }

    builder.Configuration.AddEnvironmentVariables();

    // Configure Serilog from final configuration
    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .WriteTo.Console());

    // Bind strongly typed configuration (spec §8.5)
    builder.Services.Configure<OidcOptions>(builder.Configuration.GetSection("Oidc"));
    builder.Services.Configure<AuthorizationConfig>(builder.Configuration.GetSection("Authorization"));
    builder.Services.Configure<SessionConfig>(builder.Configuration.GetSection("Session"));

    // Phase 2: Cookie Authentication
    var sessionConfig = builder.Configuration.GetSection("Session").Get<SessionConfig>() ?? new SessionConfig();
    var oidcConfig = builder.Configuration.GetSection("Oidc").Get<OidcOptions>() ?? new OidcOptions();
    bool devUseOIDC = oidcConfig.ShouldLocalDevUseOIDC;

    bool useOidcChallenge = !builder.Environment.IsDevelopment() || devUseOIDC;

    builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            if (useOidcChallenge)
            {
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            }
        })
        .AddCookie(options =>
        {
            // AC-57: Application-specific cookie name
            options.Cookie.Name = "BlazorOIDC.Auth";

            // AC-53: HttpOnly prevents JavaScript access
            options.Cookie.HttpOnly = true;

            // AC-54: Secure in production, allow HTTP in dev
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest
                : CookieSecurePolicy.Always;

            // AC-55: SameSite protection
            options.Cookie.SameSite = SameSiteMode.Lax;

            // AC-56: Mark as essential for GDPR compliance
            options.Cookie.IsEssential = true;

            // Session lifetime from config
            options.SlidingExpiration = true;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(sessionConfig.SlidingExpirationMinutes);

            // AC-58: Cookie chunking enabled by default in ASP.NET Core

            // AC-45: Dev mode redirects to /dev-login
            if (builder.Environment.IsDevelopment() && devUseOIDC == false)
            {
                options.LoginPath = "/dev-login";
            }

            options.AccessDeniedPath = "/access-denied";

            // Phase 9: Token refresh and absolute expiration enforcement
            options.Events = new CookieAuthenticationEvents
            {
                OnValidatePrincipal = async context =>
                {
                    // AC-16, AC-17: Check absolute session lifetime (24 hours)
                    var authTime = context.Properties.IssuedUtc;
                    if (authTime.HasValue)
                    {
                        var maxLifetime = TimeSpan.FromHours(sessionConfig.AbsoluteExpirationHours);
                        var elapsed = DateTimeOffset.UtcNow - authTime.Value;

                        if (elapsed > maxLifetime)
                        {
                            context.RejectPrincipal();
                            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                            Log.Information("Session rejected: absolute expiration exceeded");
                            return;
                        }
                    }

                    // AC-10, AC-11, AC-12, AC-13, AC-14: Token refresh
                    // Only attempt refresh if tokens exist (OIDC authentication)
                    if (context.Properties.Items.ContainsKey(".Token.access_token"))
                    {
                        var tokenRefreshService = context.HttpContext.RequestServices.GetRequiredService<TokenRefreshService>();
                        var originalAccessToken = context.Properties.Items[".Token.access_token"];
                        var refreshed = await tokenRefreshService.RefreshTokenIfNeededAsync(context.Principal!, context.Properties);

                        if (!refreshed)
                        {
                            // Token refresh failed, reject principal and force re-authentication
                            context.RejectPrincipal();
                            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                            Log.Information("Session rejected: token refresh failed");
                            return;
                        }

                        // If tokens were actually refreshed, reissue the cookie and replace principal
                        if (context.Properties.Items[".Token.access_token"] != originalAccessToken)
                        {
                            context.ShouldRenew = true;

                            // Spec §3.3: Replace principal with claims from new token
                            context.Properties.Items.TryGetValue(".Token.id_token", out var newIdTokenString);
                            if (!string.IsNullOrEmpty(newIdTokenString))
                            {
                                var jwtHandler = new JwtSecurityTokenHandler();
                                if (jwtHandler.CanReadToken(newIdTokenString))
                                {
                                    var newJwt = jwtHandler.ReadJwtToken(newIdTokenString);
                                    var newIdentity = new ClaimsIdentity(
                                        newJwt.Claims,
                                        "AuthenticationTypes.Federation",
                                        ClaimTypes.Name,
                                        ClaimTypes.Role);

                                    // Re-normalize roles from the new ID token
                                    // Note: During refresh, we always normalize from the ID token (which is validated and present).
                                    // The RoleClaimSource config applies only during initial login; refresh uses the ID token as the source.
                                    var normService = context.HttpContext.RequestServices.GetRequiredService<ClaimsNormalizationService>();
                                    var tokenJson = newJwt.Payload.SerializeToJson();

                                    if (tokenJson != null)
                                    {
                                        normService.NormalizeRoleClaims(tokenJson, newIdentity);
                                        var newPrincipal = new ClaimsPrincipal(newIdentity);
                                        context.ReplacePrincipal(newPrincipal);
                                    }
                                }
                            }
                        }
                    }
                }
            };
        })
        // Phase 8: OpenID Connect Authentication
        .AddOpenIdConnect(options =>
        {
            var oidcOptions = builder.Configuration.GetSection("Oidc").Get<OidcOptions>() ?? new OidcOptions();
            var clientSecret = builder.Configuration["Oidc:ClientSecret"];

            // AC-1, AC-2: Configure OIDC endpoints and client
            options.Authority = oidcOptions.Authority;
            options.ClientId = oidcOptions.ClientId;
            options.ClientSecret = clientSecret ?? string.Empty;

            // AC-5: Scopes include offline_access for refresh token
            options.Scope.Clear();
            foreach (var scope in oidcOptions.Scopes)
            {
                options.Scope.Add(scope);
            }

            // Callback paths
            options.CallbackPath = oidcOptions.CallbackPath;
            options.SignedOutCallbackPath = oidcOptions.SignedOutCallbackPath;

            // AC-3, AC-4: Authorization Code Flow with PKCE and token storage
            options.ResponseType = "code";
            options.UsePkce = true;
            options.SaveTokens = true; // Required for token refresh (AC-10)

            // Ensure cookies store tokens in authentication properties
            options.GetClaimsFromUserInfoEndpoint = false; // We'll normalize manually via OnTokenValidated

            // AC-59: Log authentication failures at Warning level
            options.Events = new OpenIdConnectEvents
            {
                OnTokenValidated = context =>
                {
                    // Phase 7: Wire claims normalization
                    var normalizationService = context.HttpContext.RequestServices.GetRequiredService<ClaimsNormalizationService>();
                    var identity = context.Principal?.Identity as ClaimsIdentity;

                    if (identity != null)
                    {
                        var authCfg = context.HttpContext.RequestServices.GetRequiredService<IOptions<AuthorizationConfig>>().Value;

                        // Serialize the appropriate token payload as JSON for the normalization service.
                        // The OIDC handler doesn't add raw tokens as claims on the principal — it maps
                        // individual JWT claims. The normalization service expects a claim containing
                        // the full JSON payload, so we add it temporarily and remove it after.
                        string? tokenJson = null;
                        if (authCfg.RoleClaimSource == "AccessToken")
                        {
                            var accessTokenString = context.TokenEndpointResponse?.AccessToken;
                            if (!string.IsNullOrEmpty(accessTokenString))
                            {
                                var jwtHandler = new JwtSecurityTokenHandler();
                                if (jwtHandler.CanReadToken(accessTokenString))
                                {
                                    tokenJson = jwtHandler.ReadJwtToken(accessTokenString).Payload.SerializeToJson();
                                }
                            }
                        }
                        else if (context.SecurityToken is JwtSecurityToken jwtToken)
                        {
                            tokenJson = jwtToken.Payload.SerializeToJson();
                        }

                        if (tokenJson != null)
                        {
                            normalizationService.NormalizeRoleClaims(tokenJson, identity);
                        }
                    }

                    return Task.CompletedTask;
                },
                OnRedirectToIdentityProviderForSignOut = context =>
                {
                    // Read id_token from HttpContext.Items (set by AuthController.Logout).
                    // We use Items instead of AuthenticationProperties to avoid serializing
                    // the token into the OIDC state parameter (causes HTTP 431).
                    if (context.HttpContext.Items["id_token_for_logout"] is string idTokenHint
                        && !string.IsNullOrEmpty(idTokenHint))
                    {
                        context.ProtocolMessage.IdTokenHint = idTokenHint;
                    }

                    return Task.CompletedTask;
                },
                OnAuthenticationFailed = context =>
                {
                    Log.Warning("OIDC authentication failed: {Exception}", context.Exception?.Message ?? "Unknown error");
                    return Task.CompletedTask;
                },
                OnRemoteFailure = context =>
                {
                    Log.Warning("OIDC remote failure: {Failure}", context.Failure?.Message ?? "Unknown error");
                    return Task.CompletedTask;
                }
            };
        });

    // Phase 3: Authorization Policies
    builder.Services.AddAuthorization(options =>
    {
        // AC-23, AC-24: CanView requires View, Edit, or Admin
        options.AddPolicy("CanView", policy =>
            policy.RequireAssertion(context =>
                context.User.HasClaim(ClaimTypes.Role, "View") ||
                context.User.HasClaim(ClaimTypes.Role, "Edit") ||
                context.User.HasClaim(ClaimTypes.Role, "Admin")));

        // AC-25, AC-26: CanEdit requires Edit or Admin
        options.AddPolicy("CanEdit", policy =>
            policy.RequireAssertion(context =>
                context.User.HasClaim(ClaimTypes.Role, "Edit") ||
                context.User.HasClaim(ClaimTypes.Role, "Admin")));

        // AC-27: IsAdmin requires Admin only
        options.AddPolicy("IsAdmin", policy =>
            policy.RequireAssertion(context =>
                context.User.HasClaim(ClaimTypes.Role, "Admin")));
    });

    // Phase 7: Claims Normalization Service
    builder.Services.AddScoped<ClaimsNormalizationService>();

    // Phase 9: Token Refresh Service
    builder.Services.AddHttpClient<TokenRefreshService>()
        .ConfigurePrimaryHttpMessageHandler(() =>
        {
            var handler = new HttpClientHandler();
            if (builder.Environment.IsDevelopment())
            {
                // Allow untrusted certificates for local OIDC provider in dev only
                handler.ServerCertificateCustomValidationCallback =
                    (message, cert, chain, errors) => true;
            }
            return handler;
        });

    // Add services to the container
    builder.Services.AddControllers();
    builder.Services.AddRazorComponents()
        .AddInteractiveServerComponents();

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Error", createScopeForErrors: true);
        app.UseHsts();
    }
    app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
    app.UseHttpsRedirection();

    app.UseSerilogRequestLogging();

    app.UseAuthentication();
    app.UseAuthorization();

    app.UseAntiforgery();

    app.MapStaticAssets();
    app.MapControllers();
    app.MapRazorComponents<App>()
        .AddInteractiveServerRenderMode();

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
