namespace BlazorOIDC.Models;

public class AuthorizationConfig
{
    public string RoleClaimSource { get; set; } = "IdToken";
    public string RoleClaimPath { get; set; } = "realm_access.roles";
}
