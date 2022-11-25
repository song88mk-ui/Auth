using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class AppRoleClaim
    {
        public string RoleId { get; set; }
        public string Category { get; set; }
        public string Name { get; set; }
        public string ClaimType { get; set; }
        public string ClaimValue { get; set; } = "0";
        public bool CheckVal { get; set; } = false;
    }
}
