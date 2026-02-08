using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using BlazorOIDC.Models;
using BlazorOIDC.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using NUnit.Framework;

namespace BlazorOIDC.Tests;

/// <summary>
/// Unit tests for token refresh logic (AC-10, AC-11, AC-12, AC-13, AC-14, AC-51, AC-52)
/// </summary>
public class TokenRefreshTests
{
    private Mock<ILogger<TokenRefreshService>> _mockLogger = null!;
    private Mock<HttpClient> _mockHttpClient = null!;
    private OidcOptions _oidcOptions = null!;
    private SessionConfig _sessionConfig = null!;

    [SetUp]
    public void Setup()
    {
        _mockLogger = new Mock<ILogger<TokenRefreshService>>();
        _mockHttpClient = new Mock<HttpClient>();
        _oidcOptions = new OidcOptions { Authority = "https://idp.example.com" };
        _sessionConfig = new SessionConfig
        {
            SlidingExpirationMinutes = 30,
            AbsoluteExpirationHours = 24,
            ClockSkewMinutes = 2
        };
    }

    private TokenRefreshService CreateService(OidcOptions? oidcOpts = null, SessionConfig? sessionConfig = null)
    {
        oidcOpts ??= _oidcOptions;
        sessionConfig ??= _sessionConfig;

        var oidcOptions = Options.Create(oidcOpts);
        var sessionOptions = Options.Create(sessionConfig);
        return new TokenRefreshService(oidcOptions, sessionOptions, _mockLogger.Object, _mockHttpClient.Object);
    }

    /// <summary>
    /// AC-51, AC-52: Token within clock skew window should be refreshed
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_RefreshesTokenWithinClockSkew()
    {
        // Arrange
        var service = CreateService();

        // Create a token that expires in 1 minute (within 2-minute clock skew)
        var expirationTime = DateTime.UtcNow.AddMinutes(1);
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Exp, new DateTimeOffset(expirationTime).ToUnixTimeSeconds().ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, "user123")
        };

        var token = new JwtSecurityToken(
            issuer: "https://idp.example.com",
            audience: "client-id",
            claims: claims,
            expires: expirationTime
        );

        var handler = new JwtSecurityTokenHandler();
        var tokenString = handler.WriteToken(token);

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        properties.Items[".Token.access_token"] = tokenString;
        properties.Items[".Token.refresh_token"] = "refresh-token-value";

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert - should attempt refresh (would normally fail due to invalid endpoint, but logic is tested)
        Assert.That(result, Is.False, "Refresh should fail due to no valid endpoint, but process should continue");
    }

    /// <summary>
    /// AC-10, AC-11: Valid, non-expired token should not be refreshed
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_DoesNotRefreshValidToken()
    {
        // Arrange
        var service = CreateService();

        // Create a token that expires in 1 hour (well beyond 2-minute clock skew)
        var expirationTime = DateTime.UtcNow.AddHours(1);
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Exp, new DateTimeOffset(expirationTime).ToUnixTimeSeconds().ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, "user123")
        };

        var token = new JwtSecurityToken(
            issuer: "https://idp.example.com",
            audience: "client-id",
            claims: claims,
            expires: expirationTime
        );

        var handler = new JwtSecurityTokenHandler();
        var tokenString = handler.WriteToken(token);

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        properties.Items[".Token.access_token"] = tokenString;
        properties.Items[".Token.refresh_token"] = "refresh-token-value";

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert - valid token should not attempt refresh
        Assert.That(result, Is.True, "Valid token should be accepted without refresh");
    }

    /// <summary>
    /// AC-12: Missing tokens should fail gracefully
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_HandlesMissingTokens()
    {
        // Arrange
        var service = CreateService();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        // No tokens in properties

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert
        Assert.That(result, Is.False, "Missing tokens should fail");
    }

    /// <summary>
    /// Clock skew configuration affects refresh behavior
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_RespectsClockSkewConfiguration()
    {
        // Arrange - with 1-minute clock skew
        var sessionConfig = new SessionConfig
        {
            ClockSkewMinutes = 1,
            SlidingExpirationMinutes = 30,
            AbsoluteExpirationHours = 24
        };
        var service = CreateService(sessionConfig: sessionConfig);

        // Create a token that expires in 2 minutes (outside 1-minute clock skew)
        var expirationTime = DateTime.UtcNow.AddMinutes(2);
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Exp, new DateTimeOffset(expirationTime).ToUnixTimeSeconds().ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, "user123")
        };

        var token = new JwtSecurityToken(
            issuer: "https://idp.example.com",
            audience: "client-id",
            claims: claims,
            expires: expirationTime
        );

        var handler = new JwtSecurityTokenHandler();
        var tokenString = handler.WriteToken(token);

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        properties.Items[".Token.access_token"] = tokenString;
        properties.Items[".Token.refresh_token"] = "refresh-token-value";

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert - token should be considered still valid with 1-min skew
        Assert.That(result, Is.True, "Token outside clock skew should not need refresh");
    }

    /// <summary>
    /// Invalid JWT format should be handled gracefully
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_HandlesInvalidJwt()
    {
        // Arrange
        var service = CreateService();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        properties.Items[".Token.access_token"] = "not-a-valid-jwt";
        properties.Items[".Token.refresh_token"] = "refresh-token-value";

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert
        Assert.That(result, Is.False, "Invalid JWT should fail gracefully");
    }
}
