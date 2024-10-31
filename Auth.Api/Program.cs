using Azure.Identity;
using Microsoft.AspNetCore.DataProtection;
using Auth.Api.ActionFilters;
using Auth.Api.Identity;
using Auth.Api.Repositories;
using Auth.Api.Services;
using Auth.Api.Telemetry;
using Auth.Shared.Data.Auth;
using Auth.Shared.Models;
using Auth.Shared.Models.Request;
using Auth.Shared.Utilities;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using OpenTelemetry.Exporter;
using OpenTelemetry.Instrumentation.AspNetCore;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using System.Diagnostics.Metrics;
using System.Reflection;
using System.Text;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// Telemetry
Action<ResourceBuilder> configureResource = r => r.AddService(
    serviceName: "Authentication-API",
    serviceNamespace: builder.Configuration["Telemetry:Environment"],
    serviceVersion: Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "latest",
    serviceInstanceId: Environment.MachineName);

builder.Services.AddSingleton<Instrumentation>();

if (Convert.ToBoolean(builder.Configuration["Telemetry:Enabled"]))
{
  builder.Services.AddOpenTelemetry()
    .ConfigureResource(configureResource)
    .WithTracing(tracing =>
    {
      tracing
        .AddSource(Instrumentation.ActivitySourceName)
        .SetSampler(new AlwaysOnSampler())
        .AddHttpClientInstrumentation(
            (options) => options.FilterHttpRequestMessage =
              (httpRequestMessage) =>
              {
                // skip calls made to azure app insights
                return !httpRequestMessage.RequestUri.Contains("monitor.azure.com") ||
                  !httpRequestMessage.RequestUri.Contains("visualstudio.com");
              }
        )
        .AddAspNetCoreInstrumentation((opts) => opts.Filter = httpContext =>
        {
          // observe /v1(/.*) only
          return httpContext.Request.Path.ToString().StartsWith("/v1");
        })
        .AddSqlClientInstrumentation();

      builder.Services.Configure<AspNetCoreTraceInstrumentationOptions>(builder.Configuration.GetSection("Telemetry:AspNetCoreInstrumentation"));


      tracing.AddOtlpExporter(otlpOptions =>
      {
        otlpOptions.Protocol = OtlpExportProtocol.HttpProtobuf;
        otlpOptions.Endpoint = new Uri(builder.Configuration["Telemetry:Collector"]+"/v1/traces");
      });


    })
    .WithMetrics(metrics =>
    {
      metrics
        .AddMeter(Instrumentation.MeterName)
        .AddRuntimeInstrumentation()
        .AddHttpClientInstrumentation()
        .AddAspNetCoreInstrumentation();

      metrics.AddOtlpExporter(otlpOptions =>
      {
        otlpOptions.Protocol = OtlpExportProtocol.HttpProtobuf;
        otlpOptions.Endpoint = new Uri(builder.Configuration["Telemetry:Collector"]+"/v1/metrics");
      });

    });

}

// Add services to the container.
builder.Services.AddDbContextPool<AuthContext>(o => o.UseSqlServer(builder.Configuration["Context:Auth"]));
builder.Services.AddIdentity<AppUser, AppRole>().AddEntityFrameworkStores<AuthContext>()
    //.AddTokenProvider("BoWeb", typeof(DataProtectorTokenProvider<AppUser>))
    .AddDefaultTokenProviders();

builder.Services.AddScoped<AuthenticationStateProvider, RevalidatingIdentityAuthenticationStateProvider<IdentityUser>>();
builder.Services.AddScoped<ApiKeyFilter>();
builder.Services.AddScoped<IAuthRepository, AuthRepository>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddControllers().AddNewtonsoftJson(options => options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore);
builder.Services.AddSingleton<IMemCache, MemCache>();
builder.Services.Configure<IdentityOptions>(options =>
{
    // Default Password settings.
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 8;
    options.Password.RequiredUniqueChars = 0;
});
builder.Services.AddHealthChecks();
builder.Services.AddApplicationInsightsTelemetry();

// configure dpk when runnin on aca
if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CONTAINER_APP_ENV_DNS_SUFFIX")))
{
  var envName = Environment.GetEnvironmentVariable("AUTH_ENV_NAME");
  var dpkUri = $"https://song88dpk.blob.core.windows.net/{envName}/auth-api/dpk";
  builder.Services.AddDataProtection()
    .PersistKeysToAzureBlobStorage(new Uri(dpkUri), new DefaultAzureCredential());
}

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
    option.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Auth API",
        Version = "v1",
        Description = "Authorization API for web apps"
    });
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

    option.DocInclusionPredicate((docName, description) => true);
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    option.IncludeXmlComments(xmlPath);
});
builder.Services.AddControllers().AddJsonOptions(options =>
            options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));


builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["JWT:Issuer"],
        ValidAudience = builder.Configuration["JWT:Issuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]))
    };
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseExceptionHandler("/error-development");
}

app.UseSwagger();
app.UseSwaggerUI(option =>
{
    option.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth API V1");
    option.DisplayRequestDuration();
});
//app.UseReDoc(option =>
//{
//    option.DocumentTitle = "Swagger Demo Documentation";
//    option.SpecUrl = "/swagger/v1/swagger.json";
//});
app.UseCors();
app.UseAuthorization();
app.MapHealthChecks("/healthz");
app.UseAuthentication();
//app.UseHttpsRedirection();

app.MapControllers();
app.Run();
