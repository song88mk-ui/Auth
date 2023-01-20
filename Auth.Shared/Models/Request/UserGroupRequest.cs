using Auth.Shared.Enums;
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
        public string SearchText { get; set; } = "";
        public string Selection { get; set; } = "";
        public string UserGroupId { get; set; } = "";
        public string UserGroupName { get; set; } = "";
        public UserSorting SortBy { get; set; } = UserSorting.SortByCreateDateDesc;
        public List<ClaimModel> Claims { get; set; } = new List<ClaimModel>();
        public MetaData MetaData { get; set; } = new MetaData();
    }
}
