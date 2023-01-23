namespace Auth.Shared.Models.Response
{
    public class ActivityLogResponse
    {
        public ActivityLogResponse()
        {
            ActivityLogs = new List<ActivityLogModel>();
        }
        public List<ActivityLogModel> ActivityLogs { get; set; }
    }
}
