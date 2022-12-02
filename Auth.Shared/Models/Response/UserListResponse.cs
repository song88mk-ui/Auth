namespace Auth.Shared.Models.Response
{
    public class UserListResponse
    {
        public UserListResponse()
        {
            Users = new List<AppUser>();
        }

        public List<AppUser> Users { get; set; }
    }
}
