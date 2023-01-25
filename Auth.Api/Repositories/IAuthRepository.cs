using Auth.Shared.Models;
using Auth.Shared.Models.Response;

namespace Auth.Api.Repositories
{
    public interface IAuthRepository
    {
        Task<BaseResponse<TokenModel>> Login(LoginModel content);
        Task<BaseResponse<bool>> Logout(string token);
        Task<BaseResponse<TokenModel>> Authenticate(string token);
        Task<BaseResponse<PermissionResponse>> GetPermissionList(bool isSubUserOnly);
        Task<BaseResponse<ActivityLogResponse>> GetActivityLogList(string userId, string search, MetaData metaData);
    }
}
