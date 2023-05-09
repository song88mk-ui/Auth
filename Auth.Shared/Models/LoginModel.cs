using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Provider { get; set; }
        public string UserAgent { get; set; } = "";
        public string IpAddress { get; set; } = "";
        public string Country { get; set; } = "";
        public DateTime Date { get; set; } = DateTime.UtcNow;
    }
}
