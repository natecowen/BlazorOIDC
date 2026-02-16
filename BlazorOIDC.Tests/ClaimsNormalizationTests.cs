using System.Security.Claims;
using System.Text.Json;
using BlazorOIDC.Models;
using BlazorOIDC.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using NUnit.Framework;

namespace BlazorOIDC.Tests;

/// <summary>
/// Unit tests for claims normalization (AC-19, AC-20, AC-21, AC-22)
/// </summary>
public class ClaimsNormalizationTests
{
    private Mock<ILogger<ClaimsNormalizationService>> _mockLogger = null!;
    private AuthorizationConfig _authConfig = null!;

    [SetUp]
    public void Setup()
    {
        _mockLogger = new Mock<ILogger<ClaimsNormalizationService>>();
        _authConfig = new AuthorizationConfig();
    }

    private ClaimsNormalizationService CreateService(AuthorizationConfig? config = null)
    {
        config ??= _authConfig;
        var options = Options.Create(config);
        return new ClaimsNormalizationService(options, _mockLogger.Object);
    }

    /// <summary>
    /// AC-19, AC-21: Extract roles from nested JSON (realm_access.roles)
    /// </summary>
    [Test]
    public void NormalizeRoleClaims_ExtractsFromNestedPath()
    {
        // Arrange
        _authConfig.RoleClaimSource = "IdToken";
        _authConfig.RoleClaimPath = "realm_access.roles";

        var service = CreateService();

        var tokenJson = JsonSerializer.Serialize(new
        {
            realm_access = new { roles = new[] { "View", "Edit" } }
        });

        var identity = new ClaimsIdentity();

        // Act
        service.NormalizeRoleClaims(tokenJson, identity);

        // Assert
        var roleClaims = identity.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        Assert.That(roleClaims, Does.Contain("View"));
        Assert.That(roleClaims, Does.Contain("Edit"));
        Assert.That(roleClaims.Count, Is.EqualTo(2));
    }

    /// <summary>
    /// AC-19, AC-21: Extract roles from flat role claim path
    /// </summary>
    [Test]
    public void NormalizeRoleClaims_ExtractsFromFlatPath()
    {
        // Arrange
        _authConfig.RoleClaimSource = "IdToken";
        _authConfig.RoleClaimPath = "roles";

        var service = CreateService();

        var tokenJson = JsonSerializer.Serialize(new
        {
            roles = new[] { "Admin", "User" }
        });

        var identity = new ClaimsIdentity();

        // Act
        service.NormalizeRoleClaims(tokenJson, identity);

        // Assert
        var roleClaims = identity.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        Assert.That(roleClaims, Does.Contain("Admin"));
        Assert.That(roleClaims, Does.Contain("User"));
    }

    /// <summary>
    /// AC-20: Support both IdToken and AccessToken sources
    /// </summary>
    [Test]
    public void NormalizeRoleClaims_SupportsAccessTokenSource()
    {
        // Arrange
        _authConfig.RoleClaimSource = "AccessToken";
        _authConfig.RoleClaimPath = "roles";

        var service = CreateService();

        var tokenJson = JsonSerializer.Serialize(new
        {
            roles = new[] { "View" }
        });

        var identity = new ClaimsIdentity();

        // Act
        service.NormalizeRoleClaims(tokenJson, identity);

        // Assert
        var roleClaims = identity.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        Assert.That(roleClaims, Does.Contain("View"));
    }

    /// <summary>
    /// AC-22: Handle missing claim paths gracefully
    /// </summary>
    [Test]
    public void NormalizeRoleClaims_HandlesMissingPath()
    {
        // Arrange
        _authConfig.RoleClaimSource = "IdToken";
        _authConfig.RoleClaimPath = "nonexistent.path";

        var service = CreateService();

        var tokenJson = JsonSerializer.Serialize(new
        {
            realm_access = new { roles = new[] { "View" } }
        });

        var identity = new ClaimsIdentity();

        // Act - should not throw
        service.NormalizeRoleClaims(tokenJson, identity);

        // Assert - no roles added
        var roleClaims = identity.FindAll(ClaimTypes.Role);
        Assert.That(roleClaims.Count, Is.EqualTo(0));
    }

    /// <summary>
    /// Calling NormalizeRoleClaims twice should not duplicate roles
    /// </summary>
    [Test]
    public void NormalizeRoleClaims_IsIdempotent()
    {
        // Arrange
        _authConfig.RoleClaimSource = "IdToken";
        _authConfig.RoleClaimPath = "realm_access.roles";

        var service = CreateService();

        var tokenJson = JsonSerializer.Serialize(new
        {
            realm_access = new { roles = new[] { "View", "Admin" } }
        });

        var identity = new ClaimsIdentity();

        // Act — call twice to simulate refresh
        service.NormalizeRoleClaims(tokenJson, identity);
        service.NormalizeRoleClaims(tokenJson, identity);

        // Assert — should still have exactly 2 role claims, not 4
        var roleClaims = identity.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        Assert.That(roleClaims.Count, Is.EqualTo(2));
        Assert.That(roleClaims, Does.Contain("View"));
        Assert.That(roleClaims, Does.Contain("Admin"));
    }

    /// <summary>
    /// AC-19: Handle single role as string (not array)
    /// </summary>
    [Test]
    public void NormalizeRoleClaims_HandlesSingleRoleAsString()
    {
        // Arrange
        _authConfig.RoleClaimSource = "IdToken";
        _authConfig.RoleClaimPath = "role";

        var service = CreateService();

        var tokenJson = JsonSerializer.Serialize(new { role = "Admin" });

        var identity = new ClaimsIdentity();

        // Act
        service.NormalizeRoleClaims(tokenJson, identity);

        // Assert
        var roleClaims = identity.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        Assert.That(roleClaims, Does.Contain("Admin"));
    }
}
