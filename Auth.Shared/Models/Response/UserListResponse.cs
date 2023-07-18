namespace Auth.Shared.Models.Response
{
    public class UserListResponse
    {
        public UserListResponse()
        {
            Users = new List<UserResponse>();
            MetaData = new MetaData();
        }

        public List<UserResponse> Users { get; set; }
        public MetaData MetaData { get; set; }
    }
}
