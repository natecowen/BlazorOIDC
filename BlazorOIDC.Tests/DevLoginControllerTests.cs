using System.Security.Claims;
using BlazorOIDC.Controllers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;

namespace BlazorOIDC.Tests;

/// <summary>
/// Unit tests for DevLoginController
/// </summary>
public class DevLoginControllerTests
{
    private Mock<ILogger<DevLoginController>> _mockLogger = null!;
    private Mock<IWebHostEnvironment> _mockEnvironment = null!;
    private Mock<HttpContext> _mockHttpContext = null!;

    [SetUp]
    public void Setup()
    {
        _mockLogger = new Mock<ILogger<DevLoginController>>();
        _mockEnvironment = new Mock<IWebHostEnvironment>();
        _mockHttpContext = new Mock<HttpContext>();
    }

    private DevLoginController CreateController()
    {
        var controller = new DevLoginController(_mockEnvironment.Object, _mockLogger.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = _mockHttpContext.Object
            }
        };
        return controller;
    }

    /// <summary>
    /// AC-40: Dev login endpoint exists in development
    /// </summary>
    [Test]
    public async Task Login_InDevelopment_CreatesSession()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Development");
        var mockAuthService = new Mock<IAuthenticationService>();

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        var controller = CreateController();

        // Act
        var result = await controller.Login("View");

        // Assert
        Assert.That(result, Is.InstanceOf<RedirectResult>());
        mockAuthService.Verify(
            x => x.SignInAsync(
                _mockHttpContext.Object,
                CookieAuthenticationDefaults.AuthenticationScheme,
                It.IsAny<ClaimsPrincipal>(),
                It.IsAny<AuthenticationProperties>()),
            Times.Once);
    }

    /// <summary>
    /// AC-41: Dev login returns 404 in production
    /// </summary>
    [Test]
    public async Task Login_InProduction_ReturnsNotFound()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");
        var controller = CreateController();

        // Act
        var result = await controller.Login("View");

        // Assert
        Assert.That(result, Is.InstanceOf<NotFoundResult>());
    }

    /// <summary>
    /// AC-42, AC-43: Dev login with View role
    /// </summary>
    [Test]
    public async Task Login_WithViewRole_CreatesSessionWithViewRole()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Development");
        var mockAuthService = new Mock<IAuthenticationService>();

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        var controller = CreateController();

        // Act
        var result = await controller.Login("View");

        // Assert
        Assert.That(result, Is.InstanceOf<RedirectResult>());
        var redirectResult = (RedirectResult)result;
        Assert.That(redirectResult.Url, Is.EqualTo("/"));

        mockAuthService.Verify(
            x => x.SignInAsync(
                It.IsAny<HttpContext>(),
                CookieAuthenticationDefaults.AuthenticationScheme,
                It.Is<ClaimsPrincipal>(p =>
                    p.FindFirst(ClaimTypes.Role) != null && p.FindFirst(ClaimTypes.Role)!.Value == "View"),
                It.IsAny<AuthenticationProperties>()),
            Times.Once);
    }

    /// <summary>
    /// AC-42, AC-43: Dev login with Edit role
    /// </summary>
    [Test]
    public async Task Login_WithEditRole_CreatesSessionWithEditRole()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Development");
        var mockAuthService = new Mock<IAuthenticationService>();

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        var controller = CreateController();

        // Act
        var result = await controller.Login("Edit");

        // Assert
        Assert.That(result, Is.InstanceOf<RedirectResult>());

        mockAuthService.Verify(
            x => x.SignInAsync(
                It.IsAny<HttpContext>(),
                CookieAuthenticationDefaults.AuthenticationScheme,
                It.Is<ClaimsPrincipal>(p =>
                    p.FindFirst(ClaimTypes.Role) != null && p.FindFirst(ClaimTypes.Role)!.Value == "Edit"),
                It.IsAny<AuthenticationProperties>()),
            Times.Once);
    }

    /// <summary>
    /// AC-42, AC-43: Dev login with Admin role
    /// </summary>
    [Test]
    public async Task Login_WithAdminRole_CreatesSessionWithAdminRole()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Development");
        var mockAuthService = new Mock<IAuthenticationService>();

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        var controller = CreateController();

        // Act
        var result = await controller.Login("Admin");

        // Assert
        Assert.That(result, Is.InstanceOf<RedirectResult>());

        mockAuthService.Verify(
            x => x.SignInAsync(
                It.IsAny<HttpContext>(),
                CookieAuthenticationDefaults.AuthenticationScheme,
                It.Is<ClaimsPrincipal>(p =>
                    p.FindFirst(ClaimTypes.Role) != null && p.FindFirst(ClaimTypes.Role)!.Value == "Admin"),
                It.IsAny<AuthenticationProperties>()),
            Times.Once);
    }

    /// <summary>
    /// AC-43: Dev login with empty role defaults to View
    /// </summary>
    [Test]
    public async Task Login_WithEmptyRole_DefaultsToView()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Development");
        var mockAuthService = new Mock<IAuthenticationService>();

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        var controller = CreateController();

        // Act
        var result = await controller.Login("");

        // Assert
        Assert.That(result, Is.InstanceOf<RedirectResult>());

        mockAuthService.Verify(
            x => x.SignInAsync(
                It.IsAny<HttpContext>(),
                CookieAuthenticationDefaults.AuthenticationScheme,
                It.Is<ClaimsPrincipal>(p =>
                    p.FindFirst(ClaimTypes.Role) != null && p.FindFirst(ClaimTypes.Role)!.Value == "View"),
                It.IsAny<AuthenticationProperties>()),
            Times.Once);
    }

    /// <summary>
    /// AC-43: Dev login redirects to home after authentication
    /// </summary>
    [Test]
    public async Task Login_RedirectsToHome()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Development");
        var mockAuthService = new Mock<IAuthenticationService>();

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        var controller = CreateController();

        // Act
        var result = await controller.Login("View");

        // Assert
        Assert.That(result, Is.InstanceOf<RedirectResult>());
        var redirectResult = (RedirectResult)result;
        Assert.That(redirectResult.Url, Is.EqualTo("/"));
    }

    /// <summary>
    /// AC-43: Dev login creates valid claims principal with proper metadata
    /// </summary>
    [Test]
    public async Task Login_CreatesPrincipalWithRequiredClaims()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Development");
        ClaimsPrincipal? capturedPrincipal = null;

        var mockAuthService = new Mock<IAuthenticationService>();
        mockAuthService
            .Setup(x => x.SignInAsync(
                It.IsAny<HttpContext>(),
                It.IsAny<string>(),
                It.IsAny<ClaimsPrincipal>(),
                It.IsAny<AuthenticationProperties>()))
            .Callback((HttpContext _, string _, ClaimsPrincipal p, AuthenticationProperties _) =>
            {
                capturedPrincipal = p;
            })
            .Returns(Task.CompletedTask);

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        var controller = CreateController();

        // Act
        await controller.Login("Admin");

        // Assert
        Assert.That(capturedPrincipal, Is.Not.Null);
        Assert.That(capturedPrincipal!.FindFirst(ClaimTypes.NameIdentifier), Is.Not.Null);
        var nameClaim = capturedPrincipal.FindFirst(ClaimTypes.Name);
        Assert.That(nameClaim, Is.Not.Null);
        Assert.That(nameClaim!.Value, Does.Contain("Admin"));
        var roleClaim = capturedPrincipal.FindFirst(ClaimTypes.Role);
        Assert.That(roleClaim, Is.Not.Null);
        Assert.That(roleClaim!.Value, Is.EqualTo("Admin"));
        var authModeClaim = capturedPrincipal.FindFirst("auth_mode");
        Assert.That(authModeClaim, Is.Not.Null);
        Assert.That(authModeClaim!.Value, Is.EqualTo("development_bypass"));
        Assert.That(capturedPrincipal.FindFirst("auth_time"), Is.Not.Null);
    }

    /// <summary>
    /// AC-43: Dev login logs successful authentication
    /// </summary>
    [Test]
    public async Task Login_LogsAuthenticationEvent()
    {
        // Arrange
        _mockEnvironment.Setup(e => e.EnvironmentName).Returns("Development");
        var mockAuthService = new Mock<IAuthenticationService>();

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        var controller = CreateController();

        // Act
        await controller.Login("View");

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, _) => v.ToString()!.Contains("View")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }
}
