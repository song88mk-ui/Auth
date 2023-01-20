namespace Auth.Shared.Models.Response
{
    public class UserGroupListResponse
    {
        public UserGroupListResponse()
        {
            UserGroups = new List<UserGroupResponse>();
            MetaData = new MetaData();
            MetaData.PageSize = 0;
        }

        public List<UserGroupResponse> UserGroups { get; set; }
        public MetaData MetaData { get; set; }
    }
}
