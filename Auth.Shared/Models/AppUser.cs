using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class AppUser : IdentityUser
    {
        public string MainUserId { get; set; }
        public int? AppId { get; set; }
        public string? AppName { get; set; }
    }
}
