using System.Security.Claims;
using BlazorOIDC.Components;
using BlazorOIDC.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
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

    builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
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
            if (builder.Environment.IsDevelopment())
            {
                options.LoginPath = "/dev-login";
            }

            options.AccessDeniedPath = "/access-denied";

            // Absolute expiration enforcement (24 hours)
            options.Events = new CookieAuthenticationEvents
            {
                OnValidatePrincipal = async context =>
                {
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
                        }
                    }
                }
            };
        });

    builder.Services.AddAuthorization();

    // Add services to the container.
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
    app.MapRazorComponents<App>()
        .AddInteractiveServerRenderMode();

    // AC-43: Dev login endpoint (development only)
    if (app.Environment.IsDevelopment())
    {
        app.MapPost("/api/dev-login", async (HttpContext context) =>
        {
            var form = await context.Request.ReadFormAsync();
            var role = form["role"].ToString();

            if (string.IsNullOrEmpty(role))
            {
                role = "View";
            }

            // Create claims for the selected role
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, $"dev-user-{Guid.NewGuid():N}"),
                new Claim(ClaimTypes.Name, $"Dev User ({role})"),
                new Claim(ClaimTypes.Role, role),
                new Claim("auth_mode", "development_bypass"),
                new Claim("auth_time", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            // Sign in and issue cookie
            await context.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                claimsPrincipal,
                new AuthenticationProperties
                {
                    IsPersistent = false,
                    IssuedUtc = DateTimeOffset.UtcNow,
                    AllowRefresh = true
                });

            Log.Information("Dev login: User authenticated with role {Role}", role);

            // Redirect to home page
            context.Response.Redirect("/");
        }).DisableAntiforgery(); // Dev-only endpoint, antiforgery not needed
    }

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
