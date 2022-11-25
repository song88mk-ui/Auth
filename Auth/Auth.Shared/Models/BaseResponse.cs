using Auth.Shared.Enums;

namespace Auth.Shared.Models
{
    public class BaseResponse<T>
    {
        public StatusCode StatusCode { get; set; }
        public string Message { get; set; }
        public T? Result { get; set; }
    }
}
