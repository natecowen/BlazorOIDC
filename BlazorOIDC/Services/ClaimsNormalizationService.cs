using System.Security.Claims;
using System.Text.Json;
using BlazorOIDC.Models;
using Microsoft.Extensions.Options;

namespace BlazorOIDC.Services;

// See architecture.md → "Claims Normalization & Role Mapping" for understanding of what this file does.

/// <summary>
/// Service for normalizing and extracting roles from token claims (AC-19, AC-20, AC-21, AC-22)
/// </summary>
public class ClaimsNormalizationService
{
    private readonly AuthorizationConfig _authConfig;
    private readonly ILogger<ClaimsNormalizationService> _logger;

    public ClaimsNormalizationService(
        IOptions<AuthorizationConfig> authConfig,
        ILogger<ClaimsNormalizationService> logger)
    {
        _authConfig = authConfig.Value;
        _logger = logger;
    }

    /// <summary>
    /// Extracts roles from the configured claim path in a token JSON string and adds them
    /// as ClaimTypes.Role claims to the ClaimsIdentity. Handles nested JSON via dot notation
    /// (e.g., "realm_access.roles").
    /// </summary>
    /// <param name="tokenJson">JWT token payload serialized as JSON</param>
    /// <param name="identity">ClaimsIdentity to add role claims to</param>
    public void NormalizeRoleClaims(string tokenJson, ClaimsIdentity identity)
    {
        if (identity == null)
        {
            _logger.LogWarning("ClaimsIdentity is null during claims normalization");
            return;
        }

        if (string.IsNullOrWhiteSpace(tokenJson))
        {
            _logger.LogWarning("Token JSON is null or empty during claims normalization");
            return;
        }

        var roles = ExtractRolesFromClaim(tokenJson);

        // Remove existing role claims to avoid duplicates on refresh
        foreach (var existing in identity.FindAll(ClaimTypes.Role).ToList())
        {
            identity.RemoveClaim(existing);
        }

        foreach (var role in roles)
        {
            if (!string.IsNullOrWhiteSpace(role))
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, role));
                _logger.LogDebug("Added role claim: {Role}", role);
            }
        }
    }

    /// <summary>
    /// Extracts role values from a claim value by parsing the path (supporting dot notation for nested JSON).
    /// Returns a list of role strings.
    /// </summary>
    private List<string> ExtractRolesFromClaim(string claimValue)
    {
        var roles = new List<string>();

        if (string.IsNullOrWhiteSpace(_authConfig.RoleClaimPath))
        {
            _logger.LogWarning("RoleClaimPath is not configured");
            return roles;
        }

        try
        {
            using var doc = JsonDocument.Parse(claimValue);
            var root = doc.RootElement;

            // Navigate the path (supports dot notation like "realm_access.roles")
            var pathParts = _authConfig.RoleClaimPath.Split('.');
            JsonElement current = root;

            foreach (var part in pathParts)
            {
                if (current.TryGetProperty(part, out var next))
                {
                    current = next;
                }
                else
                {
                    _logger.LogWarning("Could not find claim path {RoleClaimPath}", _authConfig.RoleClaimPath);
                    return roles;
                }
            }

            // Extract roles from the final element (should be an array or a single string)
            if (current.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in current.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        roles.Add(item.GetString() ?? string.Empty);
                    }
                }
            }
            else if (current.ValueKind == JsonValueKind.String)
            {
                // Single role as string
                var roleValue = current.GetString();
                if (!string.IsNullOrWhiteSpace(roleValue))
                {
                    roles.Add(roleValue);
                }
            }
            else
            {
                _logger.LogWarning("RoleClaimPath {RoleClaimPath} does not resolve to a string or array", _authConfig.RoleClaimPath);
            }
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse claim as JSON");
        }

        return roles;
    }
}
