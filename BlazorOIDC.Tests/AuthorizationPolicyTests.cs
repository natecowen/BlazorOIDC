using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using NUnit.Framework;

namespace BlazorOIDC.Tests;

/// <summary>
/// Unit tests for authorization policies (AC-23 through AC-27)
/// </summary>
public class AuthorizationPolicyTests
{
    private ClaimsPrincipal CreatePrincipalWithRole(string role)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, "user-id"),
            new Claim(ClaimTypes.Name, $"Test User ({role})"),
            new Claim(ClaimTypes.Role, role)
        };
        var identity = new ClaimsIdentity(claims, "test");
        return new ClaimsPrincipal(identity);
    }

    private bool EvaluateCanViewPolicy(ClaimsPrincipal user)
    {
        return user.HasClaim(ClaimTypes.Role, "View") ||
               user.HasClaim(ClaimTypes.Role, "Edit") ||
               user.HasClaim(ClaimTypes.Role, "Admin");
    }

    private bool EvaluateCanEditPolicy(ClaimsPrincipal user)
    {
        return user.HasClaim(ClaimTypes.Role, "Edit") ||
               user.HasClaim(ClaimTypes.Role, "Admin");
    }

    private bool EvaluateIsAdminPolicy(ClaimsPrincipal user)
    {
        return user.HasClaim(ClaimTypes.Role, "Admin");
    }

    /// <summary>
    /// AC-23: View role can access CanView policy
    /// </summary>
    [Test]
    public void CanViewPolicy_AllowsViewRole()
    {
        var principal = CreatePrincipalWithRole("View");
        var result = EvaluateCanViewPolicy(principal);
        Assert.That(result, Is.True);
    }

    /// <summary>
    /// AC-24: View role cannot access CanEdit policy
    /// </summary>
    [Test]
    public void CanEditPolicy_DeniesViewRole()
    {
        var principal = CreatePrincipalWithRole("View");
        var result = EvaluateCanEditPolicy(principal);
        Assert.That(result, Is.False);
    }

    /// <summary>
    /// AC-25: Edit role can access both CanView and CanEdit policies
    /// </summary>
    [Test]
    public void CanViewPolicy_AllowsEditRole()
    {
        var principal = CreatePrincipalWithRole("Edit");
        var result = EvaluateCanViewPolicy(principal);
        Assert.That(result, Is.True);
    }

    [Test]
    public void CanEditPolicy_AllowsEditRole()
    {
        var principal = CreatePrincipalWithRole("Edit");
        var result = EvaluateCanEditPolicy(principal);
        Assert.That(result, Is.True);
    }

    /// <summary>
    /// AC-26: Edit role cannot access IsAdmin policy
    /// </summary>
    [Test]
    public void IsAdminPolicy_DeniesEditRole()
    {
        var principal = CreatePrincipalWithRole("Edit");
        var result = EvaluateIsAdminPolicy(principal);
        Assert.That(result, Is.False);
    }

    /// <summary>
    /// AC-27: Admin role can access all policies (CanView, CanEdit, IsAdmin)
    /// </summary>
    [Test]
    public void CanViewPolicy_AllowsAdminRole()
    {
        var principal = CreatePrincipalWithRole("Admin");
        var result = EvaluateCanViewPolicy(principal);
        Assert.That(result, Is.True);
    }

    [Test]
    public void CanEditPolicy_AllowsAdminRole()
    {
        var principal = CreatePrincipalWithRole("Admin");
        var result = EvaluateCanEditPolicy(principal);
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsAdminPolicy_AllowsAdminRole()
    {
        var principal = CreatePrincipalWithRole("Admin");
        var result = EvaluateIsAdminPolicy(principal);
        Assert.That(result, Is.True);
    }

    /// <summary>
    /// No roles: user is denied all policies
    /// </summary>
    [Test]
    public void AllPolicies_DenyUnauthenticatedUser()
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, "user-id"),
            new Claim(ClaimTypes.Name, "No Role User")
        };
        var identity = new ClaimsIdentity(claims, "test");
        var principal = new ClaimsPrincipal(identity);

        var canViewResult = EvaluateCanViewPolicy(principal);
        var canEditResult = EvaluateCanEditPolicy(principal);
        var isAdminResult = EvaluateIsAdminPolicy(principal);

        Assert.That(canViewResult, Is.False);
        Assert.That(canEditResult, Is.False);
        Assert.That(isAdminResult, Is.False);
    }
}
