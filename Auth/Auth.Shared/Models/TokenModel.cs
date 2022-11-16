using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class TokenModel
    {
        public string Token { get; set; }
        public string Refresh { get; set; }
    }
}
