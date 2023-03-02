using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models.Request
{
    public class UserModifyRequest
    {
        public string? Nickname { get; set; } = null;
        public bool? IsLock { get; set; } = null;
    }
}
