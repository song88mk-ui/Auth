using Auth.Shared.Data.Auth.Entities;

namespace Auth.Shared.Models.Response
{
    public class ActivityLogResponse
    {
        public ActivityLogResponse()
        {
            ActivityLogs = new List<ActivityLog2>();
        }
        public List<ActivityLog2> ActivityLogs { get; set; }
        public MetaData MetaData { get; set; }
    }
}
