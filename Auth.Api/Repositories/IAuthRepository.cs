using Auth.Shared.Models;
using Auth.Shared.Models.Response;

namespace Auth.Api.Repositories
{
    public interface IAuthRepository
    {
        Task<BaseResponse<TokenModel>> Login(LoginModel content);
        Task<BaseResponse<TokenModel>> Authenticate(string token);
        Task<BaseResponse<PermissionResponse>> GetPermissionList(bool isSubUserOnly);
    }
}
