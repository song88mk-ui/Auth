using Auth.Api.ActionFilters;
using Auth.Api.Repositories;
using Auth.Shared.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.Net;
using AuthStatusCode = Auth.Shared.Enums.StatusCode;

namespace Auth.Api.Controllers
{
    [Route("v1")]
    [AllowAnonymous]
    [ApiController, EnableCors("AllowAllOrigins"), ServiceFilter(typeof(ApiKeyFilter))]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _authRepository;
        public AuthController(IAuthRepository authRepository)
        {
            this._authRepository = authRepository;
        }
        /// <summary>
        /// Loging credential
        /// </summary>
        /// <param name="usersdata"></param>
        /// <returns></returns>
        [HttpPost("login")]
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

        /// <summary>
        /// Authenticate JWT
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("authentication/access")]
        public async Task<IActionResult> AuthenticateAccess()
        {
            try
            {
                //
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

        /// <summary>
        /// Authenticate Operator Token
        /// </summary>
        /// <remarks>
        /// </remarks>
        /// <return></return>
        /// <response code="200">Valid operator token
        /// <para>Result = 1000 - Success</para></response>
        /// <response code="400">Bad Request
        /// <para>Result = 1001 - Bad Request</para></response>
        /// <response code="401">Unauthorizeed operator token
        /// <para>Result = 1001 - Bad Request</para></response>
        /// <response code="500">Internal Server Error
        /// <para>Result = 1002 - Internal Server Error</para></response>
        [HttpPost]
        [Route("authentication/operator")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(BaseResponse<int>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(BaseResponse<int>), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(BaseResponse<int>), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> AuthenticateToken()
        {
            try
            {
                var result = new OperatorBaseResponse<object>()
                {
                    StatusCode = (int)AuthStatusCode.Unauthorized,
                    Message = "Missing authorization",
                    Result = null
                };

                var token = HttpContext.Request.Headers["x-operator-token"].FirstOrDefault();
                if (token != null)
                {
                    result = await this._authRepository.AuthenticateOperator(token);
                }

                switch (result.StatusCode)
                {
                    case (int)AuthStatusCode.Success:
                        return Ok(result);
                    case (int)AuthStatusCode.Unauthorized:
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

        /// <summary>
        /// Authenticate JWT
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("authentication/security")]
        public async Task<IActionResult> AuthenticateSecurityCode([FromBody] AuthenticateSecurityCodeRequest request)
        {
            try
            {
                var result = new BaseResponse<TokenModel>()
                {
                    StatusCode = AuthStatusCode.Unauthorized,
                    Message = "Missing authorization"
                };

                result = await _authRepository.AuthenticateSecurityCode(request);

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
        [Route("logout")]
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

        [HttpGet]
        [Route("online")]
        public async Task<IActionResult> GetUsersOnline()
        {
            try
            {
                var result = await _authRepository.GetActiveSessions();

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