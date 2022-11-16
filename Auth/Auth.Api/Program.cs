using Auth.Api.ActionFilters;
using Auth.Api.Identity;
using Auth.Api.Repositories;
using Auth.Shared.Data.Auth;
using Auth.Shared.Data.Auth.Entities;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.OpenApi.Models;
using System;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Services.BuildServiceProvider().GetService<IConfiguration>();

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddDbContext<AuthContext>(o => o.UseSqlServer(configuration["Context:Auth"]));
builder.Services.AddDbContext<AuthIdentityContext>(o => o.UseSqlServer(configuration["Context:Auth"]), ServiceLifetime.Transient);
builder.Services.AddIdentityCore<IdentityUser>().AddEntityFrameworkStores<AuthIdentityContext>();

builder.Services.AddScoped<AuthenticationStateProvider, RevalidatingIdentityAuthenticationStateProvider<IdentityUser>>();
builder.Services.AddScoped<ApiKeyFilter>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins",
        builder =>
        {
            builder.AllowAnyOrigin()
           .AllowAnyMethod()
           .AllowAnyHeader();
        });
});
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth API", Version = "v1" });
    option.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
    {
        Name = "x-api-key",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Description = "Authorization by x-api-key inside request's header",
        Scheme = "ApiKeyScheme"
    });
    var key = new OpenApiSecurityScheme()
    {
        Reference = new OpenApiReference
        {
            Type = ReferenceType.SecurityScheme,
            Id = "ApiKey"
        },
        In = ParameterLocation.Header
    };

    var requirement = new OpenApiSecurityRequirement { { key, new List<string>() } };
    option.AddSecurityRequirement(requirement);
});
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddScoped<IAuthRepository, AuthRepository>();
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
app.UseSwagger();
app.UseSwaggerUI();

app.UseCors();
app.UseAuthorization();

app.MapControllers();

app.Run();
