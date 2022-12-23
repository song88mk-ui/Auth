using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class AppRoleClaim : ClaimModel
    {
        public string RoleId { get; set; }
        public string Category { get; set; }
        public string Name { get; set; }
        public bool CheckVal { get; set; } = false;
    }
}
