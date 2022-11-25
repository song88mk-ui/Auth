using Auth.Api.ActionFilters;
using Auth.Api.Services;
using Auth.Shared.Models;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using AuthStatusCode = Auth.Shared.Enums.StatusCode;

namespace Auth.Api.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController, EnableCors("AllowAllOrigins"), ServiceFilter(typeof(ApiKeyFilter))]
    public class UserController : ControllerBase
    {
        private IUserIdentityService _userIdentityService { get; set; }
        public UserController(IUserIdentityService userIdentityService)
        {
            _userIdentityService = userIdentityService;
        }

        // User management (Get list, password management)
        [HttpPost("register")]
        public async Task<IActionResult> Create([FromBody] UserComposeRequest user)
        {
            try
            {
                var result = await this._userIdentityService.AddAspNetUsers(user.User, user.RoleName);

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
        [HttpPost("modify")]
        public async Task<IActionResult> Update([FromBody] UserComposeRequest user)
        {
            try
            {
                var result = await this._userIdentityService.UpdateAspNetUsers(user.User, user.RoleName);

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

        // Sub management (Create, Get List user base)

        // Roles management (Create, update delete)

        // Permission
    }
}
