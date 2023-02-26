using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class AuthenticateSecurityCodeRequest
    {
        public long IdRef { get; set; }
        public string SecurityCode { get; set; }
    }
}
