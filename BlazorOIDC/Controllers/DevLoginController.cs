using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace BlazorOIDC.Controllers;

// Development-only auth bypass. See architecture.md → "Development Authentication" for better understanding of why this exists


/// <summary>
/// Development-only controller for bypassing OIDC authentication during local development
/// This controller is only available when IHostEnvironment.IsDevelopment() is true
/// </summary>
[ApiController]
[Route("api/dev-login")]
public class DevLoginController : ControllerBase
{
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<DevLoginController> _logger;

    public DevLoginController(
        IWebHostEnvironment environment,
        ILogger<DevLoginController> logger)
    {
        _environment = environment;
        _logger = logger;
    }

    /// <summary>
    /// Development login endpoint (AC-43)
    /// Creates an authenticated session with the selected role for local development
    /// Only available when IHostEnvironment.IsDevelopment() returns true
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> Login([FromForm] string role = "View")
    {
        // Only allow in development
        if (!_environment.IsDevelopment())
        {
            return NotFound();
        }

        // Whitelist valid roles
        string[] allowedRoles = ["View", "Edit", "Admin"];
        if (string.IsNullOrEmpty(role) || !allowedRoles.Contains(role, StringComparer.OrdinalIgnoreCase))
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
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            claimsPrincipal,
            new AuthenticationProperties
            {
                IsPersistent = false,
                IssuedUtc = DateTimeOffset.UtcNow,
                AllowRefresh = true
            });

        _logger.LogInformation("Dev login: User authenticated with role {Role}", role);

        // Redirect to home page
        return Redirect("/");
    }
}
