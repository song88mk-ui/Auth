using Auth.Shared.Models;
using Auth_Api.Utilities;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController, EnableCors("AllowAllOrigins"), ServiceFilter(typeof(ApiKeyFilter))]
    public class AuthController : ControllerBase
    {
        private readonly IJwtManagerRepository _jwtManager;

        public Authentication(IJwtManagerRepository jWTManager)
        {
            this._jwtManager = jWTManager;
        }

        [HttpPost]
        [Route("/authenticate")]
        public IActionResult Authenticate(UserModel usersdata)
        {
            var token = _jwtManager.Authenticate(usersdata);

            if (token == null)
            {
                return Unauthorized(token);
            }

            return Ok(token);
        }
    }
}
