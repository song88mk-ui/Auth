using Auth.Api.ActionFilters;
using Auth.Api.Repositories;
using Auth.Shared.Models;
using Azure.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AuthStatusCode = Auth.Shared.Enums.StatusCode;

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

        [HttpPost("/login")]
        public async Task<IActionResult> Login(LoginModel usersdata)
        {
            try
            {
                var result = await this._authRepository.Login(usersdata);

                switch (result.StatusCode)
                {
                    case AuthStatusCode.Success:
                        return Ok(result);
                    case AuthStatusCode.Unauthorized:
                        return Unauthorized(result);
                    default:
                        return BadRequest(result);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        [HttpGet]
        [Route("/authenticate")]
        public async Task<IActionResult> Authenticate()
        {
            try
            {
                var result = new BaseResponse<TokenModel>()
                {
                    StatusCode = AuthStatusCode.Unauthorized,
                    Message = "Missing authorization"
                };
                if (HttpContext.Request.Headers.ContainsKey("Authorization"))
                {
                    var token = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
                    result = await this._authRepository.Authenticate(token);
                }

                switch (result.StatusCode)
                {
                    case AuthStatusCode.Success:
                        return Ok(result);
                    case AuthStatusCode.Unauthorized:
                        return Unauthorized(result);
                    default:
                        return BadRequest(result);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        [HttpGet]
        [Route("/logout")]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var result = new BaseResponse<bool>()
                {
                    StatusCode = AuthStatusCode.Unauthorized,
                    Message = "Missing authorization"
                };
                if (HttpContext.Request.Headers.ContainsKey("Authorization"))
                {
                    var token = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
                    result = await this._authRepository.Logout(token);
                }

                switch (result.StatusCode)
                {
                    case AuthStatusCode.Success:
                        return Ok(result);
                    case AuthStatusCode.Unauthorized:
                        return Unauthorized(result);
                    default:
                        return BadRequest(result);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }
    }
}