using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using BlazorOIDC.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace BlazorOIDC.Services;

// See architecture.md → "Token Refresh & Session Management" for understanding of what this file does.


/// <summary>
/// Service for handling token refresh and validation (AC-10 through AC-14, AC-51, AC-52, AC-60, AC-61, AC-62)
/// </summary>
public class TokenRefreshService
{
    private readonly OidcOptions _oidcOptions;
    private readonly SessionConfig _sessionConfig;
    private readonly ILogger<TokenRefreshService> _logger;
    private readonly HttpClient _httpClient;
    private string? _cachedTokenEndpoint;

    public TokenRefreshService(
        IOptions<OidcOptions> oidcOptions,
        IOptions<SessionConfig> sessionConfig,
        ILogger<TokenRefreshService> logger,
        HttpClient httpClient)
    {
        _oidcOptions = oidcOptions.Value;
        _sessionConfig = sessionConfig.Value;
        _logger = logger;
        _httpClient = httpClient;
    }

    /// <summary>
    /// Checks if token is expired or nearing expiry within the clock skew window,
    /// and refreshes it if needed.
    /// </summary>
    public async Task<bool> RefreshTokenIfNeededAsync(
        ClaimsPrincipal principal,
        AuthenticationProperties properties)
    {
        try
        {
            // Extract tokens from properties
            if (!properties.Items.TryGetValue(".Token.access_token", out var accessToken) ||
                !properties.Items.TryGetValue(".Token.refresh_token", out var refreshToken))
            {
                _logger.LogWarning("Access token or refresh token not found in authentication properties");
                return false;
            }

            // Parse access token to check expiry
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(accessToken))
            {
                _logger.LogWarning("Cannot read access token");
                return false;
            }

            var token = handler.ReadJwtToken(accessToken);
            var expiryTime = token.ValidTo;
            var clockSkew = TimeSpan.FromMinutes(_sessionConfig.ClockSkewMinutes);
            var now = DateTime.UtcNow;

            // AC-51, AC-52: Check if token is expired or within clock skew window
            if (expiryTime > now.Add(clockSkew))
            {
                // Token is still valid, no refresh needed
                return true;
            }

            _logger.LogDebug("Token is expired or within clock skew window, attempting refresh");

            // Refresh the token via the OIDC token endpoint
            var refreshed = await RefreshAccessTokenAsync(refreshToken, properties);
            if (!refreshed)
            {
                // AC-12, AC-13: On failure, return false and let the principal be rejected
                _logger.LogWarning("Token refresh failed, session will be rejected");
                return false;
            }

            // AC-60, AC-61: Log successful refresh
            _logger.LogInformation("Token refresh successful");
            return true;
        }
        catch (Exception ex)
        {
            // AC-62: Never log token contents
            _logger.LogWarning(ex, "Exception during token refresh");
            return false;
        }
    }

    /// <summary>
    /// Calls the OIDC token endpoint to refresh the access token using the refresh token.
    /// Parses the response and updates tokens in AuthenticationProperties in-place.
    /// </summary>
    private async Task<bool> RefreshAccessTokenAsync(string? refreshToken, AuthenticationProperties properties)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            _logger.LogWarning("Refresh token is null or empty");
            return false;
        }

        try
        {
            var tokenEndpoint = await GetTokenEndpointAsync();
            if (string.IsNullOrEmpty(tokenEndpoint))
            {
                _logger.LogWarning("Could not determine token endpoint from OIDC discovery");
                return false;
            }

            var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "client_id", _oidcOptions.ClientId },
                    { "client_secret", _oidcOptions.ClientSecret },
                    { "grant_type", "refresh_token" },
                    { "refresh_token", refreshToken }
                })
            };

            var response = await _httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "Token endpoint returned {StatusCode}: {ReasonPhrase}",
                    response.StatusCode,
                    response.ReasonPhrase);
                return false;
            }

            // AC-10, AC-11: Parse token endpoint response
            var content = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonSerializer.Deserialize<JsonElement>(content);

            if (!tokenResponse.TryGetProperty("access_token", out var newAccessToken))
            {
                _logger.LogWarning("Token response missing access_token");
                return false;
            }

            // AC-14: Validate new ID token if present
            if (tokenResponse.TryGetProperty("id_token", out var newIdToken))
            {
                var idTokenString = newIdToken.GetString();
                if (!ValidateIdToken(idTokenString))
                {
                    _logger.LogWarning("New ID token validation failed");
                    return false;
                }
                properties.Items[".Token.id_token"] = idTokenString;
            }

            // Update tokens in AuthenticationProperties
            properties.Items[".Token.access_token"] = newAccessToken.GetString()!;

            if (tokenResponse.TryGetProperty("refresh_token", out var newRefreshToken))
            {
                properties.Items[".Token.refresh_token"] = newRefreshToken.GetString()!;
            }

            if (tokenResponse.TryGetProperty("expires_in", out var expiresIn))
            {
                var expiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn.GetInt32());
                properties.Items[".Token.expires_at"] = expiresAt.ToString("o");
            }

            return true;
        }
        catch (HttpRequestException ex)
        {
            // AC-13: IdP unreachable
            _logger.LogWarning(ex, "Failed to reach OIDC token endpoint");
            return false;
        }
    }

    /// <summary>
    /// Discovers the token endpoint from the OIDC provider's .well-known/openid-configuration.
    /// Caches the result for the lifetime of this service instance.
    /// </summary>
    private async Task<string?> GetTokenEndpointAsync()
    {
        if (_cachedTokenEndpoint != null)
            return _cachedTokenEndpoint;

        try
        {
            var discoveryUrl = $"{_oidcOptions.Authority}/.well-known/openid-configuration";
            var response = await _httpClient.GetAsync(discoveryUrl);
            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();
            var doc = JsonDocument.Parse(content);

            if (doc.RootElement.TryGetProperty("token_endpoint", out var endpoint))
            {
                _cachedTokenEndpoint = endpoint.GetString();
                return _cachedTokenEndpoint;
            }

            _logger.LogWarning("OIDC discovery document missing token_endpoint");
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to fetch OIDC discovery document");
            return null;
        }
    }

    /// <summary>
    /// Validates a new ID token by checking issuer and expiry.
    /// </summary>
    private bool ValidateIdToken(string? idToken)
    {
        if (string.IsNullOrWhiteSpace(idToken))
            return false;

        var handler = new JwtSecurityTokenHandler();
        if (!handler.CanReadToken(idToken))
            return false;

        var token = handler.ReadJwtToken(idToken);

        // Verify issuer matches configured authority
        if (!string.Equals(token.Issuer, _oidcOptions.Authority, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("ID token issuer mismatch: expected {Expected}, got {Actual}", _oidcOptions.Authority, token.Issuer);
            return false;
        }

        // Verify token is not expired
        if (token.ValidTo < DateTime.UtcNow)
        {
            _logger.LogWarning("New ID token is already expired");
            return false;
        }

        return true;
    }
}
