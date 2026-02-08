using BlazorOIDC.Configuration;
using Microsoft.Extensions.Configuration;

namespace BlazorOIDC.Tests;

public class ConfigurationTests
{
    private IConfigurationRoot BuildTestConfiguration(
        Dictionary<string, string?>? overrides = null)
    {
        var builder = new ConfigurationBuilder()
            .SetBasePath(TestContext.CurrentContext.TestDirectory)
            .AddJsonFile("Configs/oidc.json", optional: false)
            .AddJsonFile("Configs/authorization.json", optional: false);

        if (overrides != null)
        {
            builder.AddInMemoryCollection(overrides);
        }

        return builder.Build();
    }

    // AC-46: Config files load and bind to POCOs
    [Test]
    public void OidcJson_BindsTo_OidcOptions()
    {
        var config = BuildTestConfiguration();
        var oidc = new OidcOptions();
        config.GetSection("Oidc").Bind(oidc);

        Assert.That(oidc.CallbackPath, Is.EqualTo("/signin-oidc"));
        Assert.That(oidc.SignedOutCallbackPath, Is.EqualTo("/signout-callback-oidc"));
        Assert.That(oidc.Scopes, Does.Contain("openid"));
        Assert.That(oidc.Scopes, Does.Contain("offline_access"));
    }

    // AC-47: Authorization config loads correctly
    [Test]
    public void AuthorizationJson_BindsTo_AuthorizationConfig()
    {
        var config = BuildTestConfiguration();
        var auth = new AuthorizationConfig();
        config.GetSection("Authorization").Bind(auth);

        Assert.That(auth.RoleClaimSource, Is.EqualTo("IdToken"));
        Assert.That(auth.RoleClaimPath, Is.EqualTo("realm_access.roles"));
    }

    // AC-47: Session config loads correctly
    [Test]
    public void AuthorizationJson_BindsTo_SessionConfig()
    {
        var config = BuildTestConfiguration();
        var session = new SessionConfig();
        config.GetSection("Session").Bind(session);

        Assert.That(session.SlidingExpirationMinutes, Is.EqualTo(30));
        Assert.That(session.AbsoluteExpirationHours, Is.EqualTo(24));
        Assert.That(session.ClockSkewMinutes, Is.EqualTo(2));
    }

    // AC-48 / AC-49: Higher-priority sources override JSON values
    [Test]
    public void HigherPrioritySource_Overrides_JsonValues()
    {
        var overrides = new Dictionary<string, string?>
        {
            ["Oidc:Authority"] = "https://override.example.com",
            ["Oidc:ClientId"] = "override-client"
        };

        var config = BuildTestConfiguration(overrides);
        var oidc = new OidcOptions();
        config.GetSection("Oidc").Bind(oidc);

        Assert.That(oidc.Authority, Is.EqualTo("https://override.example.com"));
        Assert.That(oidc.ClientId, Is.EqualTo("override-client"));
    }

    // AC-50: ClientSecret must not appear in config JSON files
    [Test]
    public void OidcJson_DoesNotContain_ClientSecret()
    {
        var configPath = Path.Combine(
            TestContext.CurrentContext.TestDirectory, "Configs", "oidc.json");
        var content = File.ReadAllText(configPath);

        Assert.That(content, Does.Not.Contain("ClientSecret"),
            "ClientSecret must not be stored in config files — use user-secrets or env vars");
    }

    // AC-48: Config loading order - later sources win
    [Test]
    public void ConfigurationOrder_LaterSourcesWin()
    {
        var builder = new ConfigurationBuilder()
            .SetBasePath(TestContext.CurrentContext.TestDirectory)
            .AddJsonFile("Configs/oidc.json", optional: false)
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Oidc:Authority"] = "from-first-override"
            })
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Oidc:Authority"] = "from-second-override"
            });

        var config = builder.Build();
        Assert.That(config["Oidc:Authority"], Is.EqualTo("from-second-override"));
    }
}
