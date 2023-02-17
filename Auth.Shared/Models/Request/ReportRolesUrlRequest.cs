using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class ReportRolesUrlRequest
    {
        public string RoleId { get; set; }
        public string ClaimType { get; set; }
    }
}
