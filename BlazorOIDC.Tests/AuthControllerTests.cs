using System.Security.Claims;
using BlazorOIDC.Controllers;
using BlazorOIDC.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using NUnit.Framework;

namespace BlazorOIDC.Tests;

/// <summary>
/// Unit tests for AuthController (Login, Logout, SignoutCallback)
/// </summary>
public class AuthControllerTests
{
    private Mock<ILogger<AuthController>> _mockLogger = null!;
    private Mock<IOptions<OidcOptions>> _mockOidcOptions = null!;
    private Mock<HttpContext> _mockHttpContext = null!;
    private OidcOptions _oidcOptions = null!;

    [SetUp]
    public void Setup()
    {
        _mockLogger = new Mock<ILogger<AuthController>>();
        _oidcOptions = new OidcOptions
        {
            Authority = "https://idp.example.com",
            ClientId = "test-client",
            ClientSecret = "test-secret"
        };
        _mockOidcOptions = new Mock<IOptions<OidcOptions>>();
        _mockOidcOptions.Setup(x => x.Value).Returns(_oidcOptions);

        _mockHttpContext = new Mock<HttpContext>();
        _mockHttpContext.Setup(x => x.Request.Scheme).Returns("https");
        _mockHttpContext.Setup(x => x.Request.Host).Returns(new HostString("localhost:7064"));
    }

    private AuthController CreateController()
    {
        var controller = new AuthController(_mockOidcOptions.Object, _mockLogger.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = _mockHttpContext.Object
            }
        };
        return controller;
    }

    /// <summary>
    /// AC-35: Login action redirects to /dev-login in development
    /// </summary>
    [Test]
    public void Login_InDevelopment_RedirectsToDevLogin()
    {
        // Arrange
        var controller = CreateController();
        var mockEnvironment = new Mock<IWebHostEnvironment>();
        mockEnvironment.Setup(e => e.EnvironmentName).Returns("Development");

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IWebHostEnvironment)))
            .Returns(mockEnvironment.Object);

        // Act
        var result = controller.Login();

        // Assert
        Assert.That(result, Is.InstanceOf<RedirectResult>());
        var redirectResult = (RedirectResult)result;
        Assert.That(redirectResult.Url, Is.EqualTo("/dev-login"));
    }

    /// <summary>
    /// AC-35: Login action triggers OIDC challenge in production
    /// </summary>
    [Test]
    public void Login_InProduction_TriggersOidcChallenge()
    {
        // Arrange
        var controller = CreateController();
        var mockEnvironment = new Mock<IWebHostEnvironment>();
        mockEnvironment.Setup(e => e.EnvironmentName).Returns("Production");

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IWebHostEnvironment)))
            .Returns(mockEnvironment.Object);

        // Act
        var result = controller.Login();

        // Assert
        Assert.That(result, Is.InstanceOf<ChallengeResult>());
        var challengeResult = (ChallengeResult)result;
        Assert.That(challengeResult.AuthenticationSchemes, Does.Contain("OpenIdConnect"));
    }

    /// <summary>
    /// AC-6, AC-36: Logout signs out the user
    /// </summary>
    [Test]
    public async Task Logout_SignsOutUser()
    {
        // Arrange
        var controller = CreateController();
        var mockAuthService = new Mock<IAuthenticationService>();

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        // User has no id_token (not OIDC authenticated)
        var claims = new List<Claim> { new Claim(ClaimTypes.Name, "testuser") };
        var identity = new ClaimsIdentity(claims, "test");
        var principal = new ClaimsPrincipal(identity);
        _mockHttpContext.Setup(x => x.User).Returns(principal);

        // Act
        var result = await controller.Logout();

        // Assert
        mockAuthService.Verify(
            x => x.SignOutAsync(
                _mockHttpContext.Object,
                "Cookies",
                It.IsAny<AuthenticationProperties>()),
            Times.Once);
    }

    /// <summary>
    /// AC-9: Logout without OIDC redirects to home
    /// </summary>
    [Test]
    public async Task Logout_WithoutOidc_RedirectsToHome()
    {
        // Arrange
        var controller = CreateController();
        var mockAuthService = new Mock<IAuthenticationService>();

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        // User has no id_token
        var claims = new List<Claim> { new Claim(ClaimTypes.Name, "testuser") };
        var identity = new ClaimsIdentity(claims, "test");
        var principal = new ClaimsPrincipal(identity);
        _mockHttpContext.Setup(x => x.User).Returns(principal);

        // Act
        var result = await controller.Logout();

        // Assert
        Assert.That(result, Is.InstanceOf<RedirectResult>());
        var redirectResult = (RedirectResult)result;
        Assert.That(redirectResult.Url, Is.EqualTo("/"));
    }

    /// <summary>
    /// AC-8: Logout with OIDC redirects through end-session endpoint
    /// </summary>
    [Test]
    public async Task Logout_WithOidc_RedirectsToEndSession()
    {
        // Arrange
        var controller = CreateController();
        var mockAuthService = new Mock<IAuthenticationService>();

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        // User has id_token (OIDC authenticated)
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, "testuser"),
            new Claim("id_token", "test-token-value")
        };
        var identity = new ClaimsIdentity(claims, "test");
        var principal = new ClaimsPrincipal(identity);
        _mockHttpContext.Setup(x => x.User).Returns(principal);

        // Act
        var result = await controller.Logout();

        // Assert
        Assert.That(result, Is.InstanceOf<RedirectResult>());
        var redirectResult = (RedirectResult)result;
        Assert.That(redirectResult.Url, Does.Contain("https://idp.example.com"));
        Assert.That(redirectResult.Url, Does.Contain("/protocol/openid-connect/logout"));
        Assert.That(redirectResult.Url, Does.Contain("post_logout_redirect_uri=https%3A%2F%2Flocalhost%3A7064%2F"));
    }

    /// <summary>
    /// SignoutCallback redirects to home
    /// </summary>
    [Test]
    public void SignoutCallback_RedirectsToHome()
    {
        // Arrange
        var controller = CreateController();

        // Act
        var result = controller.SignoutCallback();

        // Assert
        Assert.That(result, Is.InstanceOf<RedirectResult>());
        var redirectResult = (RedirectResult)result;
        Assert.That(redirectResult.Url, Is.EqualTo("/"));
    }

}
