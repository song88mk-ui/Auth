using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class UsersOnlineResponse
    {
        public UsersOnlineResponse()
        {
            OnlineUsers = new List<long>();
        }
        public List<long> OnlineUsers { get; set; }
    }
}
