using Auth.Shared.Models;
using Auth.Shared.Models.Response;

namespace Auth.Api.Repositories
{
    public interface IAuthRepository
    {
        Task<BaseResponse<TokenModel>> Login(LoginModel content);
        Task<BaseResponse<bool>> Logout(string token, bool isOperator = false);
        BaseResponse<TokenModel> Authenticate(string token);
        OperatorBaseResponse<object> AuthenticateOperator(string token, bool isAgent = false);
        Task<BaseResponse<TokenModel>> AuthenticateSecurityCode(AuthenticateSecurityCodeRequest request);
        Task<BaseResponse<PermissionResponse>> GetPermissionList(bool isSubUserOnly, int version, string categories = "0,1,2");
        Task<BaseResponse<ActivityLogResponse>> GetActivityLogList(string userId, string search, MetaData metaData);
        Task<BaseResponse<UsersOnlineResponse>> GetActiveSessions();
    }
}
