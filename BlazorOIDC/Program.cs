using BlazorOIDC.Components;
using BlazorOIDC.Configuration;
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

    app.UseAntiforgery();

    app.MapStaticAssets();
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
