using Microsoft.AspNetCore.Identity;

namespace Auth.Shared.Models
{
    public class AppRole : IdentityRole
    {
        public AppRole()
        {

        }

        public AppRole(string roleName) : base(roleName)
        {
            Name = roleName;
        }

        public long UserGroupIdRef { get; set; }
    }
}
