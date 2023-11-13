using CookingMedia.Gateway.Authentication;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
var authUrl = builder.Configuration.GetValue<Uri>("AuthUrl");
builder.Services.AddHttpClient(
    "Auth",
    client =>
    {
        client.BaseAddress = authUrl;
    }
);

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCors();
builder.Services
    .AddAuthentication(opt =>
    {
        opt.DefaultAuthenticateScheme = ServerTokenAuthenticationDefaults.AuthenticationScheme;
        opt.DefaultChallengeScheme = ServerTokenAuthenticationDefaults.AuthenticationScheme;
    })
    .AddServerToken(options =>
    {
        options.Host = "http";
    });

var ocelotConfiguration = new ConfigurationBuilder().AddJsonFile("ocelot.json").Build();
builder.Services.AddOcelot(ocelotConfiguration);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors(opts =>
{
    opts.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
});

app.UseHttpsRedirection();

// app.UseAuthorization();
app.UseOcelot();

// TODO: author for POST and PUT

app.MapControllers();

app.Run();
