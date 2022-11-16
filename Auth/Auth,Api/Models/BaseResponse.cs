using Microsoft.AspNetCore.Http;

namespace Auth_Api.Models
{
    public class BaseResponse
    {
        public StatusCode StatusCode { get; set; }
        public string Message { get; set; }
        public T Result { get; set; }
    }
}
