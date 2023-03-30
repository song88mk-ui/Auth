using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models.Request
{
    public class UserModifyRequest
    {
        public string? Nickname { get; set; } = "";
        public string? Status { get; set; } = "";
        public string? OldPassword { get; set; } = "";
        public string? Password { get; set; } = "";
        public List<ClaimModel>? Claims { get; set; } = null;
    }
}
