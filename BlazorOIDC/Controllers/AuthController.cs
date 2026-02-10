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
    public IActionResult Login([FromForm] string? returnUrl = null)
    {
        // Validate returnUrl to prevent open redirect
        if (string.IsNullOrEmpty(returnUrl) || !Url.IsLocalUrl(returnUrl))
        {
            returnUrl = "/";
        }

        if (HttpContext.RequestServices.GetRequiredService<IWebHostEnvironment>().IsDevelopment() && _oidcOptions.ShouldLocalDevUseOIDC == false)
        {
            // In development, redirect to dev-login page
            return Redirect("/dev-login");
        }

        // Trigger OIDC challenge with return URL
        return Challenge(new AuthenticationProperties
        {
            RedirectUri = returnUrl
        }, "OpenIdConnect");
    }

    /// <summary>
    /// Logout endpoint (AC-6, AC-8, AC-9, AC-36)
    /// Clears cookie and triggers full OIDC end-session (Keycloak → Azure AD)
    /// </summary>
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        // Get id_token BEFORE signing out (cookie clearing destroys it)
        var idToken = await HttpContext.GetTokenAsync("id_token");

        if (!string.IsNullOrEmpty(idToken) && !string.IsNullOrWhiteSpace(_oidcOptions.Authority))
        {
            // Pass id_token via HttpContext.Items — request-scoped, never serialized.
            // Using AuthenticationProperties.StoreTokens causes HTTP 431 because
            // the token gets serialized into the OIDC state parameter.
            HttpContext.Items["id_token_for_logout"] = idToken;

            return SignOut(
                new AuthenticationProperties { RedirectUri = "/" },
                CookieAuthenticationDefaults.AuthenticationScheme,
                "OpenIdConnect");
        }

        // Dev-login or no IdP: just clear the cookie
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        _logger.LogInformation("User logged out");
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
