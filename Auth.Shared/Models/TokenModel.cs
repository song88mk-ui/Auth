using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class TokenModel
    {
        public string UserName { get; set; }
        public string NickName { get; set; }
        public string OperatorToken { get; set; }
        public string AccessToken { get; set; }
    }
}
