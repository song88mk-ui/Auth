using Auth.Shared.Data.Auth.Entities;
using Auth.Shared.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Data.Auth
{
    public sealed class AuthContext : IdentityDbContext<AppUser, AppRole, string, IdentityUserClaim<string>, IdentityUserRole<string>, IdentityUserLogin<string>, IdentityRoleClaim<string>, AppToken>
    {
        public AuthContext(DbContextOptions<AuthContext> options) : base(options) { }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<ActivityLog>().HasKey(k => new { k.Id });
            builder.Entity<Permission>().HasKey(k => new { k.PermissionId });
            builder.Entity<ReportRoles>().HasKey(k => new { k.RoleId, k.ClaimType });
            base.OnModelCreating(builder);

            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);
        }
        public DbSet<ActivityLog> ActivityLog { get; set; }
        public DbSet<Permission> Permission { get; set; }
        public DbSet<ReportRoles> ReportRoles { get; set; }
    }
}
