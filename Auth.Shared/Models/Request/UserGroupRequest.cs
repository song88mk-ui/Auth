using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Models
{
    public class UserGroupRequest
    {
        public UserGroupRequest()
        {
            Claims = new List<ClaimModel>();
        }
        public string UserGroupId { get; set; }
        public string UserGroupName { get; set; }
        public List<ClaimModel> Claims { get; set; }
    }
}
