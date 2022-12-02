namespace Auth.Shared.Models.Request
{
    public class SubAccountListRequest
    {
        public string MainUserId { get; set; }
        public int Page { get; set; }
        public int PageSize { get; set; }
    }
}
