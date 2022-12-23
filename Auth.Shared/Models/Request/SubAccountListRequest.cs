namespace Auth.Shared.Models.Request
{
    public class SubAccountListRequest
    {
        public string MainUserId { get; set; }
        public string SearchText { get; set; }
        public int Page { get; set; } = 1;
        public int PageSize { get; set; } = 10;
    }
}
