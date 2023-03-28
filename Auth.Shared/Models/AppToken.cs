using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class AppToken : IdentityUserToken<string>
    {
        public string OperatorToken { get; set; }
        public DateTime SessionExpirationDate { get; set; }
    }
}
