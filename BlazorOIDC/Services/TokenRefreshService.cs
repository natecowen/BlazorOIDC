using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using BlazorOIDC.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace BlazorOIDC.Services;

/// <summary>
/// Service for handling token refresh and validation (AC-10 through AC-14, AC-51, AC-52, AC-60, AC-61, AC-62)
/// </summary>
public class TokenRefreshService
{
    private readonly OidcOptions _oidcOptions;
    private readonly SessionConfig _sessionConfig;
    private readonly ILogger<TokenRefreshService> _logger;
    private readonly HttpClient _httpClient;

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
            var refreshed = await RefreshAccessTokenAsync(refreshToken);
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
    /// Assumes standard OIDC token endpoint at {Authority}/protocol/openid-connect/token
    /// </summary>
    private async Task<bool> RefreshAccessTokenAsync(string? refreshToken)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            _logger.LogWarning("Refresh token is null or empty");
            return false;
        }

        try
        {
            // Construct token endpoint URL (standard OIDC convention)
            var tokenEndpoint = $"{_oidcOptions.Authority.TrimEnd('/')}/protocol/openid-connect/token";

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

            // TODO: Parse response and update tokens in properties (Phase 9 continuation)
            // For now, just indicate success if we got a 200 response
            return true;
        }
        catch (HttpRequestException ex)
        {
            // AC-13: IdP unreachable
            _logger.LogWarning(ex, "Failed to reach OIDC token endpoint");
            return false;
        }
    }
}
