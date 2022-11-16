using Auth.Shared.Models;

namespace Auth_Api.Services
{
    public interface IJwtService
    {
        BaseResponse<TokenModel> Authenticate(UserModel user);
    }
}
