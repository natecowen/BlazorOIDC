using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
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
    private OidcOptions _oidcOptions = null!;
    private SessionConfig _sessionConfig = null!;

    private const string TestAuthority = "https://idp.example.com";

    [SetUp]
    public void Setup()
    {
        _mockLogger = new Mock<ILogger<TokenRefreshService>>();
        _oidcOptions = new OidcOptions
        {
            Authority = TestAuthority,
            ClientId = "test-client",
            ClientSecret = "test-secret"
        };
        _sessionConfig = new SessionConfig
        {
            SlidingExpirationMinutes = 30,
            AbsoluteExpirationHours = 24,
            ClockSkewMinutes = 2
        };
    }

    private TokenRefreshService CreateService(HttpClient httpClient, OidcOptions? oidcOpts = null, SessionConfig? sessionConfig = null)
    {
        oidcOpts ??= _oidcOptions;
        sessionConfig ??= _sessionConfig;

        var oidcOptions = Options.Create(oidcOpts);
        var sessionOptions = Options.Create(sessionConfig);
        return new TokenRefreshService(oidcOptions, sessionOptions, _mockLogger.Object, httpClient);
    }

    private static string CreateTestJwt(DateTime expires, string issuer = TestAuthority)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, "user123")
        };

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: "test-client",
            claims: claims,
            expires: expires
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static HttpClient CreateMockHttpClient(HttpStatusCode statusCode, string? responseBody = null)
    {
        var handler = new MockHttpMessageHandler(statusCode, responseBody ?? "");
        return new HttpClient(handler);
    }

    /// <summary>
    /// AC-51, AC-52: Token within clock skew window should be refreshed
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_RefreshesTokenWithinClockSkew()
    {
        // Arrange — token expires in 1 minute (within 2-minute clock skew)
        var newAccessToken = CreateTestJwt(DateTime.UtcNow.AddHours(1));
        var newIdToken = CreateTestJwt(DateTime.UtcNow.AddHours(1), TestAuthority);
        var responseBody = JsonSerializer.Serialize(new
        {
            access_token = newAccessToken,
            refresh_token = "new-refresh-token",
            id_token = newIdToken,
            expires_in = 3600
        });

        var httpClient = CreateMockHttpClient(HttpStatusCode.OK, responseBody);
        var service = CreateService(httpClient);

        var tokenString = CreateTestJwt(DateTime.UtcNow.AddMinutes(1));

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        properties.Items[".Token.access_token"] = tokenString;
        properties.Items[".Token.refresh_token"] = "refresh-token-value";

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert
        Assert.That(result, Is.True, "Refresh should succeed with valid token response");
        Assert.That(properties.Items[".Token.access_token"], Is.EqualTo(newAccessToken));
        Assert.That(properties.Items[".Token.refresh_token"], Is.EqualTo("new-refresh-token"));
        Assert.That(properties.Items[".Token.id_token"], Is.EqualTo(newIdToken));
        Assert.That(properties.Items.ContainsKey(".Token.expires_at"), Is.True);
    }

    /// <summary>
    /// AC-10, AC-11: Valid, non-expired token should not be refreshed
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_DoesNotRefreshValidToken()
    {
        // Arrange — token expires in 1 hour (well beyond 2-minute clock skew)
        var httpClient = CreateMockHttpClient(HttpStatusCode.OK);
        var service = CreateService(httpClient);

        var tokenString = CreateTestJwt(DateTime.UtcNow.AddHours(1));

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        properties.Items[".Token.access_token"] = tokenString;
        properties.Items[".Token.refresh_token"] = "refresh-token-value";

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert — valid token should not attempt refresh
        Assert.That(result, Is.True, "Valid token should be accepted without refresh");
    }

    /// <summary>
    /// AC-12: Missing tokens should fail gracefully
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_HandlesMissingTokens()
    {
        // Arrange
        var httpClient = CreateMockHttpClient(HttpStatusCode.OK);
        var service = CreateService(httpClient);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();

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
        // Arrange — with 1-minute clock skew
        var sessionConfig = new SessionConfig
        {
            ClockSkewMinutes = 1,
            SlidingExpirationMinutes = 30,
            AbsoluteExpirationHours = 24
        };
        var httpClient = CreateMockHttpClient(HttpStatusCode.OK);
        var service = CreateService(httpClient, sessionConfig: sessionConfig);

        // Token expires in 2 minutes (outside 1-minute clock skew)
        var tokenString = CreateTestJwt(DateTime.UtcNow.AddMinutes(2));

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        properties.Items[".Token.access_token"] = tokenString;
        properties.Items[".Token.refresh_token"] = "refresh-token-value";

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert — token should be considered still valid with 1-min skew
        Assert.That(result, Is.True, "Token outside clock skew should not need refresh");
    }

    /// <summary>
    /// Invalid JWT format should be handled gracefully
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_HandlesInvalidJwt()
    {
        // Arrange
        var httpClient = CreateMockHttpClient(HttpStatusCode.OK);
        var service = CreateService(httpClient);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        properties.Items[".Token.access_token"] = "not-a-valid-jwt";
        properties.Items[".Token.refresh_token"] = "refresh-token-value";

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert
        Assert.That(result, Is.False, "Invalid JWT should fail gracefully");
    }

    /// <summary>
    /// AC-13: Token endpoint failure should reject session
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_HandlesTokenEndpointFailure()
    {
        // Arrange — endpoint returns 401
        var httpClient = CreateMockHttpClient(HttpStatusCode.Unauthorized);
        var service = CreateService(httpClient);

        var tokenString = CreateTestJwt(DateTime.UtcNow.AddSeconds(30)); // expired within skew

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        properties.Items[".Token.access_token"] = tokenString;
        properties.Items[".Token.refresh_token"] = "refresh-token-value";

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert
        Assert.That(result, Is.False, "Token endpoint failure should reject session");
    }

    /// <summary>
    /// AC-14: Invalid ID token in refresh response should fail
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_RejectsInvalidIdToken()
    {
        // Arrange — response has an ID token with wrong issuer
        var newAccessToken = CreateTestJwt(DateTime.UtcNow.AddHours(1));
        var badIdToken = CreateTestJwt(DateTime.UtcNow.AddHours(1), "https://evil.example.com");
        var responseBody = JsonSerializer.Serialize(new
        {
            access_token = newAccessToken,
            refresh_token = "new-refresh-token",
            id_token = badIdToken,
            expires_in = 3600
        });

        var httpClient = CreateMockHttpClient(HttpStatusCode.OK, responseBody);
        var service = CreateService(httpClient);

        var tokenString = CreateTestJwt(DateTime.UtcNow.AddSeconds(30));

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        properties.Items[".Token.access_token"] = tokenString;
        properties.Items[".Token.refresh_token"] = "refresh-token-value";

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert
        Assert.That(result, Is.False, "Mismatched ID token issuer should fail validation");
    }

    /// <summary>
    /// AC-10: Successful refresh should update all tokens in properties
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_UpdatesAllTokensOnSuccess()
    {
        // Arrange
        var newAccessToken = CreateTestJwt(DateTime.UtcNow.AddHours(1));
        var newIdToken = CreateTestJwt(DateTime.UtcNow.AddHours(1), TestAuthority);
        var responseBody = JsonSerializer.Serialize(new
        {
            access_token = newAccessToken,
            refresh_token = "rotated-refresh-token",
            id_token = newIdToken,
            expires_in = 3600
        });

        var httpClient = CreateMockHttpClient(HttpStatusCode.OK, responseBody);
        var service = CreateService(httpClient);

        var tokenString = CreateTestJwt(DateTime.UtcNow.AddSeconds(-10)); // already expired

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        properties.Items[".Token.access_token"] = tokenString;
        properties.Items[".Token.refresh_token"] = "old-refresh-token";

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(properties.Items[".Token.access_token"], Is.EqualTo(newAccessToken));
        Assert.That(properties.Items[".Token.refresh_token"], Is.EqualTo("rotated-refresh-token"));
        Assert.That(properties.Items[".Token.id_token"], Is.EqualTo(newIdToken));
    }

    /// <summary>
    /// Response without refresh_token should keep the old one
    /// </summary>
    [Test]
    public async Task RefreshTokenIfNeeded_KeepsOldRefreshTokenWhenNotRotated()
    {
        // Arrange — response has no refresh_token (no rotation)
        var newAccessToken = CreateTestJwt(DateTime.UtcNow.AddHours(1));
        var responseBody = JsonSerializer.Serialize(new
        {
            access_token = newAccessToken,
            expires_in = 3600
        });

        var httpClient = CreateMockHttpClient(HttpStatusCode.OK, responseBody);
        var service = CreateService(httpClient);

        var tokenString = CreateTestJwt(DateTime.UtcNow.AddSeconds(-10));

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()));
        var properties = new AuthenticationProperties();
        properties.Items[".Token.access_token"] = tokenString;
        properties.Items[".Token.refresh_token"] = "original-refresh-token";

        // Act
        var result = await service.RefreshTokenIfNeededAsync(principal, properties);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(properties.Items[".Token.refresh_token"], Is.EqualTo("original-refresh-token"));
    }
}

/// <summary>
/// Mock HTTP handler for testing token refresh HTTP calls
/// </summary>
public class MockHttpMessageHandler : HttpMessageHandler
{
    private readonly HttpStatusCode _statusCode;
    private readonly string _responseBody;

    public MockHttpMessageHandler(HttpStatusCode statusCode, string responseBody)
    {
        _statusCode = statusCode;
        _responseBody = responseBody;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = new HttpResponseMessage(_statusCode)
        {
            Content = new StringContent(_responseBody, Encoding.UTF8, "application/json")
        };
        return Task.FromResult(response);
    }
}
