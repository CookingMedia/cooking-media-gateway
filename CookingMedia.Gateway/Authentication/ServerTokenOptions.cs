using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace CookingMedia.Gateway.Authentication;

public class ServerTokenOptions : JwtBearerOptions
{
    public string? Host { get; set; }
}