namespace Auth.Shared.Models.Response
{
    public class UserResponse
    {
        public string UserId { get; set; }
        public string? NickName { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string MainUserId { get; set; }
        public DateTime? CreatedDate { get; set; }
        public int AppId { get; set; }
        public string AppName { get; set; }
    }
}
