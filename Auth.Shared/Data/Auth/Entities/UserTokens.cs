using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Data.Auth.Entities
{
    public class UserTokens
    {
        public string Id { get; set; }
        public string UserId { get; set; }
        public string TokenType { get; set; }
        public string AccessToken { get; set; }
        public DateTime TokenExpiration { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime RefreshExpiration { get; set; }
    }
}
