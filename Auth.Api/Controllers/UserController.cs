using Auth.Api.ActionFilters;
using Auth.Api.Repositories;
using Auth.Api.Services;
using Auth.Shared.Models;
using Auth.Shared.Models.Request;
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
        private readonly IAuthRepository _authRepository;

        public UserController(IUserIdentityService userIdentityService, IAuthRepository authRepository)
        {
            _userIdentityService = userIdentityService;
            _authRepository = authRepository;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Create([FromBody] UserRegisterRequest request)
        {
            try
            {
                var result = await _userIdentityService.AddAspNetUsers(request);

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
        public async Task<IActionResult> Update([FromBody] UserRegisterRequest request)
        {
            try
            {
                var result = await _userIdentityService.UpdateAspNetUsers(request);

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

        [HttpGet("{userId}")]
        public async Task<IActionResult> GetCurrentUser(string userId)
        {
            try
            {
                var result = await _userIdentityService.GetCurrentUser(userId);

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

        [HttpPost("subaccount/list")]
        public async Task<IActionResult> GetSubAccounts([FromBody] SubAccountListRequest request)
        {
            try
            {
                var result = await _userIdentityService.GetAspNetSubAccountList(request);

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

        [HttpGet("permission/list")]
        public async Task<IActionResult> GetPermissionList([FromQuery] bool isSubUserOnly)
        {
            var result = await _authRepository.GetPermissionList(isSubUserOnly);

            switch (result.StatusCode)
            {
                case AuthStatusCode.Success:
                    return Ok(result);
                default:
                    return BadRequest(result);
            }
        }

        [HttpPost("usergroup/list")]
        public async Task<IActionResult> GetUserGroupList([FromBody] UserGroupListRequest request)
        {
            var result = await _userIdentityService.GetAspNetRolesList(request);

            switch (result.StatusCode)
            {
                case AuthStatusCode.Success:
                    return Ok(result);
                default:
                    return BadRequest(result);
            }
        }

        [HttpPost("usergroup/user/list")]
        public async Task<IActionResult> GetUserGroupUsers([FromBody] UserGroupRequest request)
        {
            var result = await _userIdentityService.GetAspNetRoleUsers(request);

            switch (result.StatusCode)
            {
                case AuthStatusCode.Success:
                    return Ok(result);
                default:
                    return BadRequest(result);
            }
        }

        [HttpPost("usergroup/post")]
        public async Task<IActionResult> AddOrUpdateUserGroup([FromBody] UserGroupRequest request)
        {
            try
            {
                var result = await _userIdentityService.AddOrUpdateAspNetRoles(request);

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

        [HttpPost("usergroup/delete")]
        public async Task<IActionResult> DeleteUserGroup([FromBody] UserGroupRequest request)
        {
            try
            {
                var result = await _userIdentityService.DeleteAspNetRoles(request);

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
