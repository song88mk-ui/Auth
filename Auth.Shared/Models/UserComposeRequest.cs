using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class UserComposeRequest
    {
        public AppUser User { get; set; }
        public string RoleName { get; set; }
        public string Status { get; set; }
    }
}
