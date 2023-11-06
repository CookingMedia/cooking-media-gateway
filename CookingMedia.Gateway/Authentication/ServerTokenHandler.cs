using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace CookingMedia.Gateway.Authentication;

public class ServerTokenHandler : AuthenticationHandler<ServerTokenOptions>
{
    private readonly HttpClient _authClient;

    public ServerTokenHandler(
        IHttpClientFactory httpClientFactory,
        IOptionsMonitor<ServerTokenOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock
    )
        : base(options, logger, encoder, clock)
    {
        _authClient = httpClientFactory.CreateClient("Auth");
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var authorization = Request.Headers.Authorization.ToString();

            if (string.IsNullOrEmpty(authorization))
                return AuthenticateResult.NoResult();

            if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return AuthenticateResult.NoResult();

            var token = authorization.Substring("Bearer ".Length).Trim();

            if (string.IsNullOrEmpty(token))
                return AuthenticateResult.NoResult();

            var (principal, validatedToken) = await ValidateToken(token);

            var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
            {
                Principal = principal,
                SecurityToken = validatedToken
            };

            tokenValidatedContext.Success();
            return tokenValidatedContext.Result;
        }
        catch (Exception ex)
        {
            var authenticationFailedContext = new AuthenticationFailedContext(
                Context,
                Scheme,
                Options
            )
            {
                Exception = ex
            };

            return authenticationFailedContext.Result;
        }
    }

    private async Task<(ClaimsPrincipal, SecurityToken)> ValidateToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw LogHelper.LogArgumentNullException(nameof(token));

        var validateTokenResult = await _authClient.GetAsync($"v1/auth/verify?token={token}");
        if (!validateTokenResult.IsSuccessStatusCode)
            throw new UnauthorizedAccessException();

        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = jwtTokenHandler.ReadJwtToken(token);

        return (new ClaimsPrincipal(new ClaimsIdentity(jwtToken.Claims, Scheme.Name)), jwtToken);
    }
}
