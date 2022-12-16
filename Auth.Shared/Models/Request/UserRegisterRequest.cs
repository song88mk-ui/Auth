using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class UserRegisterRequest
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string MainUserId { get; set; }
        public int AppId { get; set; }
        public string AppName { get; set; }
        public string RoleName { get; set; }
        public string Status { get; set; }
        public List<Claim>? UserClaims { get; set; }
    }
}
