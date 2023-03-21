namespace Auth.Shared.Models.Response
{
    public class UserGroupResponse
    {
        public UserGroupResponse()
        {
            Claims = new List<ClaimModel>();
        }
        public string UserGroupId { get; set; }
        public long UserGroupIdRef { get; set; }
        public string UserGroupName { get; set; }
        public List<ClaimModel> Claims { get; set; }
        public int UserCount { get; set; }
    }
}
