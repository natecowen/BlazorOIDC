using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using BlazorOIDC.Models;

namespace BlazorOIDC.Controllers;

/// <summary>
/// Authentication controller handling login, logout, and OIDC callbacks
/// </summary>
[ApiController]
[Route("")]
public class AuthController : ControllerBase
{
    private readonly OidcOptions _oidcOptions;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IOptions<OidcOptions> oidcOptions,
        ILogger<AuthController> logger)
    {
        _oidcOptions = oidcOptions.Value;
        _logger = logger;
    }

    /// <summary>
    /// Login endpoint (AC-35)
    /// In development, redirects to dev-login page
    /// In production, triggers OIDC challenge
    /// </summary>
    [HttpPost("login")]
    public IActionResult Login()
    {
        if (HttpContext.RequestServices.GetRequiredService<IWebHostEnvironment>().IsDevelopment())
        {
            // In development, redirect to dev-login page
            return Redirect("/dev-login");
        }

        // In production, trigger OIDC challenge
        return Challenge(new AuthenticationProperties
        {
            RedirectUri = "/"
        }, "OpenIdConnect");
    }

    /// <summary>
    /// Logout endpoint (AC-6, AC-36, AC-8, AC-9)
    /// Clears the authentication cookie and optionally redirects through IdP end-session
    /// </summary>
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        // AC-6: Clear the local authentication cookie
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        _logger.LogInformation("User logged out");

        // AC-8, AC-9: Check if user authenticated via OIDC (has id_token) and IdP end-session is configured
        // Dev-login sessions won't have id_token, so they'll skip end-session
        var hasIdToken = User.FindFirst("id_token") != null;
        if (hasIdToken && !string.IsNullOrWhiteSpace(_oidcOptions.Authority))
        {
            try
            {
                // Construct the end-session endpoint URL (standard OIDC convention)
                var endSessionEndpoint = $"{_oidcOptions.Authority.TrimEnd('/')}/protocol/openid-connect/logout";

                // Build the post_logout_redirect_uri parameter
                var scheme = HttpContext.Request.Scheme;
                var host = HttpContext.Request.Host;
                var redirectUri = $"{scheme}://{host}/";

                // Redirect to IdP end-session endpoint
                var logoutUrl = $"{endSessionEndpoint}?post_logout_redirect_uri={Uri.EscapeDataString(redirectUri)}";
                return Redirect(logoutUrl);
            }
            catch (Exception ex)
            {
                // AC-9: If end-session fails or is not configured, silently redirect to home
                _logger.LogWarning(ex, "Failed to construct end-session URL, redirecting to home");
            }
        }

        // AC-9: If IdP end-session endpoint is not configured or user used dev-login, redirect directly to home
        return Redirect("/");
    }

    /// <summary>
    /// OIDC signed-out callback (handles redirect from IdP end-session)
    /// </summary>
    [HttpGet("signout-callback-oidc")]
    public IActionResult SignoutCallback()
    {
        // IdP has confirmed logout, redirect to home
        return Redirect("/");
    }
}
