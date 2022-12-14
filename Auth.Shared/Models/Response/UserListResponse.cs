namespace Auth.Shared.Models.Response
{
    public class UserListResponse
    {
        public UserListResponse()
        {
            Users = new List<UserResponse>();
        }

        public List<UserResponse> Users { get; set; }
    }
}
