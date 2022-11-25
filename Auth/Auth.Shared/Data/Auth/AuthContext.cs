using Auth.Shared.Data.Auth.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Data.Auth
{
    public class AuthContext : DbContext
    {
        public AuthContext(DbContextOptions<AuthContext> options) : base(options)
        {
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<AspNetRoleClaims>().HasKey(k => new { k.Id });
            modelBuilder.Entity<AspNetRoles>().HasKey(k => new { k.Id });
            modelBuilder.Entity<AspNetUserClaims>().HasKey(k => new { k.Id });
            modelBuilder.Entity<AspNetUserRoles>().HasKey(k => new { k.UserId });
            modelBuilder.Entity<AspNetUsers>().HasKey(k => new { k.Id });
            modelBuilder.Entity<Tokens>().HasKey(k => new { k.Id });
        }
        public DbSet<AspNetRoleClaims> AspNetRoleClaims { get; set; }
        public DbSet<AspNetRoles> AspNetRoles { get; set; }
        public DbSet<AspNetUserClaims> AspNetUserClaims { get; set; }
        public DbSet<AspNetUserRoles> AspNetUserRoles { get; set; }
        public DbSet<AspNetUsers> AspNetUsers { get; set; }
        public DbSet<Tokens> Tokens { get; set; }
    }
}
