using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class TokenCacheModel : TokenModel
    {
        public DateTime SessionExpirationDate { get; set; }
        public string UserId { get; set; }
        public long UserIdRef { get; set; }
    }
}
