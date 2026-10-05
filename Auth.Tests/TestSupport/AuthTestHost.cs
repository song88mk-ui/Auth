using Auth.Api.Repositories;
using Auth.Api.Services;
using Auth.Api.Telemetry;
using Auth.Shared.Data.Auth;
using Auth.Shared.Data.Auth.Entities;
using Auth.Shared.Models;
using Auth.Shared.Utilities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Tests.TestSupport
{
    /// <summary>
    /// Builds AuthService and AuthRepository the same way Program.cs does, but on an
    /// EF Core in-memory database (one per test) instead of SQL Server.
    /// </summary>
    public sealed class AuthTestHost : IDisposable
    {
        public const string JwtKey = "test-signing-key-0123456789abcdef0123456789";
        public const string Issuer = "bo.auth.api";
        public const string DefaultPassword = "Passw0rdA";

        private readonly ServiceProvider _provider;
        private readonly IServiceScope _scope;

        public AuthTestHost()
        {
            var config = new ConfigurationBuilder().AddInMemoryCollection().Build();
            config["JWT:Key"] = JwtKey;
            config["JWT:Issuer"] = Issuer;

            var databaseName = Guid.NewGuid().ToString();
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDataProtection();
            services.AddSingleton<IConfiguration>(config);
            services.AddDbContext<AuthContext>(o => o
                .UseInMemoryDatabase(databaseName, b => b.EnableNullChecks(false))
                .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning)));
            services.AddIdentityCore<AppUser>()
                .AddRoles<AppRole>()
                .AddEntityFrameworkStores<AuthContext>()
                .AddDefaultTokenProviders();
            services.AddScoped<IUserValidator<AppUser>, RejectNickNameValidator>();
            // Same password rules as Program.cs
            services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = true;
                options.Password.RequiredLength = 8;
                options.Password.RequiredUniqueChars = 0;
            });
            services.AddSingleton<IMemCache, MemCache>();
            services.AddSingleton<Instrumentation>();
            services.AddScoped<IAuthService, AuthService>();
            services.AddScoped<AuthService>();
            services.AddScoped<AuthRepository>();

            _provider = services.BuildServiceProvider();
            _scope = _provider.CreateScope();
        }

        public IServiceProvider Services => _scope.ServiceProvider;
        public AuthContext Context => Services.GetRequiredService<AuthContext>();
        public UserManager<AppUser> UserManager => Services.GetRequiredService<UserManager<AppUser>>();
        public RoleManager<AppRole> RoleManager => Services.GetRequiredService<RoleManager<AppRole>>();
        public AuthService AuthService => Services.GetRequiredService<AuthService>();
        public AuthRepository AuthRepository => Services.GetRequiredService<AuthRepository>();

        /// <summary>
        /// A fresh context on the same database, for seeding and for asserting what was persisted. Seeding through
        /// the services' own context would leave the rows tracked, which never happens in a real request.
        /// </summary>
        public AuthContext NewContext()
        {
            var options = Services.GetRequiredService<DbContextOptions<AuthContext>>();
            return new AuthContext(options);
        }

        public async Task<AppUser> CreateUserAsync(string userName, string mainUserId = "", long idRef = 0,
            int appId = (int)Shared.Enums.Application.Backoffice, string role = "")
        {
            var user = new AppUser
            {
                UserName = userName,
                NickName = $"{userName}-nick",
                Email = $"{userName}@example.com",
                IdRef = idRef,
                MainUserId = mainUserId,
                AppId = appId,
                AppName = "Backoffice",
                CreatedDate = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            };

            var result = await UserManager.CreateAsync(user, DefaultPassword);
            Assert.True(result.Succeeded, string.Join(",", result.Errors.Select(e => e.Description)));

            if (!string.IsNullOrEmpty(role))
                Assert.True((await UserManager.AddToRoleAsync(user, role)).Succeeded);

            return user;
        }

        public async Task<AppRole> CreateRoleAsync(string name, long userGroupIdRef = 0)
        {
            var role = new AppRole(name) { UserGroupIdRef = userGroupIdRef };
            Assert.True((await RoleManager.CreateAsync(role)).Succeeded);
            return role;
        }

        public Permission AddPermission(string claimType, int categoryId = 1, int version = 0, bool isSubUser = false,
            bool hasReadOnly = false, int sortOrder = 0)
        {
            var permission = new Permission
            {
                PermissionId = Guid.NewGuid(),
                CategoryId = categoryId,
                CategoryName = "Category",
                SubCategoryName = "SubCategory",
                GroupName = "Group",
                Name = claimType,
                ClaimType = claimType,
                HasReadOnly = hasReadOnly,
                SortOrder = sortOrder,
                IsSubUser = isSubUser,
                Version = version
            };
            using var context = NewContext();
            context.Permission.Add(permission);
            context.SaveChanges();
            return permission;
        }

        public void AddRoleClaim(AppRole role, Permission permission, string value)
        {
            using var context = NewContext();
            context.RoleClaims.Add(new IdentityRoleClaim<string>
            {
                RoleId = role.Id,
                ClaimType = permission.PermissionId.ToString(),
                ClaimValue = value
            });
            context.SaveChanges();
        }

        public void AddUserClaim(AppUser user, string claimType, string value)
        {
            using var context = NewContext();
            context.UserClaims.Add(new IdentityUserClaim<string>
            {
                UserId = user.Id,
                ClaimType = claimType,
                ClaimValue = value
            });
            context.SaveChanges();
        }

        public void AddUserToken(AppUser user, string value)
        {
            using var context = NewContext();
            context.UserTokens.Add(new AppToken
            {
                UserId = user.Id,
                LoginProvider = "1001",
                Name = user.UserName!,
                Value = value,
                OperatorToken = Guid.NewGuid().ToString(),
                SessionExpirationDate = DateTime.UtcNow.AddMonths(1)
            });
            context.SaveChanges();
        }

        public void Dispose()
        {
            _scope.Dispose();
            _provider.Dispose();
        }
    }
}
