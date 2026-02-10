using System.Security.Claims;
using BlazorOIDC.Controllers;
using BlazorOIDC.Models;
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
    /// AC-6, AC-9: Logout without OIDC clears cookie and redirects to home
    /// </summary>
    [Test]
    public async Task Logout_WithoutOidc_ClearsCookieAndRedirectsToHome()
    {
        // Arrange: no id_token (dev-login user)
        var controller = CreateController();
        var mockAuthService = new Mock<IAuthenticationService>();

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        // Act
        var result = await controller.Logout();

        // Assert
        mockAuthService.Verify(
            x => x.SignOutAsync(
                _mockHttpContext.Object,
                "Cookies",
                It.IsAny<AuthenticationProperties>()),
            Times.Once);

        Assert.That(result, Is.InstanceOf<RedirectResult>());
        Assert.That(((RedirectResult)result).Url, Is.EqualTo("/"));
    }

    /// <summary>
    /// AC-8, AC-6: Logout with OIDC triggers SignOut with both schemes,
    /// passing id_token via HttpContext.Items to avoid HTTP 431
    /// </summary>
    [Test]
    public async Task Logout_WithOidc_ReturnsSignOutResultWithBothSchemesAndTokenInItems()
    {
        // Arrange
        var controller = CreateController();
        var mockAuthService = new Mock<IAuthenticationService>();
        var items = new Dictionary<object, object?>();

        var properties = new AuthenticationProperties();
        properties.StoreTokens([new AuthenticationToken { Name = "id_token", Value = "test-token-value" }]);

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "testuser") }, "test"));
        _mockHttpContext.Setup(x => x.User).Returns(principal);
        _mockHttpContext.Setup(x => x.Items).Returns(items);

        mockAuthService
            .Setup(x => x.AuthenticateAsync(_mockHttpContext.Object, It.IsAny<string>()))
            .ReturnsAsync(AuthenticateResult.Success(new AuthenticationTicket(principal, properties, "Cookies")));

        _mockHttpContext.Setup(x => x.RequestServices.GetService(typeof(IAuthenticationService)))
            .Returns(mockAuthService.Object);

        // Act
        var result = await controller.Logout();

        // Assert
        Assert.That(result, Is.InstanceOf<SignOutResult>());
        var signOutResult = (SignOutResult)result;
        Assert.That(signOutResult.AuthenticationSchemes, Does.Contain("Cookies"));
        Assert.That(signOutResult.AuthenticationSchemes, Does.Contain("OpenIdConnect"));
        Assert.That(signOutResult.Properties?.RedirectUri, Is.EqualTo("/"));
        Assert.That(items["id_token_for_logout"], Is.EqualTo("test-token-value"));
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
        Assert.That(((RedirectResult)result).Url, Is.EqualTo("/"));
    }

}
