using Auth.Api.ActionFilters;
using Auth.Api.Repositories;
using Auth.Shared.Models;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;

namespace Auth.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController, EnableCors("AllowAllOrigins"), ServiceFilter(typeof(ApiKeyFilter))]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _authRepository;
        public AuthController(IAuthRepository authRepository)
        {
            this._authRepository = authRepository;
        }

        [HttpPost]
        [Route("/authenticate")]
        public async Task<IActionResult> Authenticate(UserModel usersdata)
        {
            try
            {
                var token = await this._authRepository.Authenticate(usersdata);

                switch (token.StatusCode)
                {
                    case Auth.Shared.Enums.StatusCode.Success:
                        return Ok(token);
                    case Auth.Shared.Enums.StatusCode.Unauthorized:
                        return Unauthorized(token);
                    default:
                        return BadRequest(token);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }
        [HttpGet]
        [Route("/authenticate")]
        public async Task<IActionResult> Refresh([FromQuery] string refreshToken)
        {
            try
            {
                var token = await this._authRepository.Authenticate(refreshToken);

                switch (token.StatusCode)
                {
                    case Auth.Shared.Enums.StatusCode.Success:
                        return Ok(token);
                    case Auth.Shared.Enums.StatusCode.Unauthorized:
                        return Unauthorized(token);
                    default:
                        return BadRequest(token);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        // Crate validate token
    }
}
