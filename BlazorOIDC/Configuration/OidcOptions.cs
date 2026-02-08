namespace BlazorOIDC.Configuration;

public class OidcOptions
{
    public string Authority { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string[] Scopes { get; set; } = ["openid", "profile", "roles", "offline_access"];
    public string CallbackPath { get; set; } = "/signin-oidc";
    public string SignedOutCallbackPath { get; set; } = "/signout-callback-oidc";
}
