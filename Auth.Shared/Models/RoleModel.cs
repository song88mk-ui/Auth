using Microsoft.AspNetCore.Identity;

namespace Auth.Shared.Models
{
    public class RoleModel : IdentityRole
    {
        public int UserCount { get; set; }
    }
}
