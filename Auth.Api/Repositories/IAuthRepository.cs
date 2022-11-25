using Auth.Shared.Models;

namespace Auth.Api.Repositories
{
    public interface IAuthRepository
    {
        Task<BaseResponse<TokenModel>> Authenticate(UserModel content);
        Task<BaseResponse<TokenModel>> Authenticate(string content);
        Task<BaseResponse<bool>> Validate(string content);
    }
}
