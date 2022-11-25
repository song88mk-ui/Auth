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
        public int RowNumber { get; set; }
        public string Status { get; set; }
    }
}
