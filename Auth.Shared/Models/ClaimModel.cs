using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class ClaimModel
    {
        public string ClaimType { get; set; }
        public string ClaimValue { get; set; } = "0";

    }
}
