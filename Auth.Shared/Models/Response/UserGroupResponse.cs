namespace Auth.Shared.Models.Response
{
    public class UserGroupResponse
    {
        public UserGroupResponse()
        {
            Claims = new List<ClaimModel>();
        }
        public string UserGroupId { get; set; }
        public int UserGroupIdRef { get; set; }
        public string UserGroupName { get; set; }
        public List<ClaimModel> Claims { get; set; }
    }
}
