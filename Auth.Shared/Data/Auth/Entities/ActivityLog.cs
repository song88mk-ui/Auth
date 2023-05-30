using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Data.Auth.Entities
{
    public class ActivityLog
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string Token { get; set; }
        public string UserAgent { get; set; }
        public string IpAddress { get; set; }
        public string Country { get; set; }
        public DateTime Date { get; set; }
    }
}
