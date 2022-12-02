using Auth.Shared.Models;
using Auth.Shared.Models.Response;

namespace Auth.Api.Repositories
{
    public interface IAuthRepository
    {
        Task<BaseResponse<TokenModel>> Authenticate(UserModel content);
        Task<BaseResponse<TokenModel>> Authenticate(string content);
        Task<BaseResponse<bool>> Validate(string content);
        Task<BaseResponse<PermissionResponse>> GetPermissionList(bool isSubUserOnly);
    }
}
