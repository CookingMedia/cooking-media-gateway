using Microsoft.AspNetCore.Authentication;

namespace CookingMedia.Gateway.Authentication;

public static class ServerTokenExtensions
{
    public static AuthenticationBuilder AddServerToken(this AuthenticationBuilder builder, Action<ServerTokenOptions> configureOptions)
    {
        return builder.AddScheme<ServerTokenOptions, ServerTokenHandler>(ServerTokenAuthenticationDefaults.AuthenticationScheme, null, configureOptions);
    }
}