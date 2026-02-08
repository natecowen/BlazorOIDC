using BlazorOIDC.Components;
using BlazorOIDC.Configuration;

var builder = WebApplication.CreateBuilder(args);

// Load separate config files (spec §8.1)
builder.Configuration.AddJsonFile("Configs/oidc.json", optional: false, reloadOnChange: true);
builder.Configuration.AddJsonFile("Configs/authorization.json", optional: false, reloadOnChange: true);

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
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
