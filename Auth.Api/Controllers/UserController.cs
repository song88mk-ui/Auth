using Auth.Api.ActionFilters;
using Auth.Api.Repositories;
using Auth.Api.Services;
using Auth.Shared.Models;
using Auth.Shared.Models.Request;
using Auth.Shared.Models.Response;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using AuthStatusCode = Auth.Shared.Enums.StatusCode;

namespace Auth.Api.Controllers
{
    [Authorize]
    [Route("v1/api/[controller]")]
    [ApiController, EnableCors("AllowAllOrigins"), ServiceFilter(typeof(ApiKeyFilter))]
    public class UserController : ControllerBase
    {
        private IAuthService _userIdentityService { get; set; }
        private readonly IAuthRepository _authRepository;

        public UserController(IAuthService userIdentityService, IAuthRepository authRepository)
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
        [HttpPost("modify/{userId}")]
        public async Task<IActionResult> Update([FromRoute] string userid, [FromBody] UserModifyRequest request)
        {
            try
            {
                var userRequest = new UserRegisterRequest()
                {
                    UserId = userid,
                    UserIdRef = 0,
                    UserName = "",
                    Email = "",
                    Password = request.Password,
                    NickName = request.Nickname,
                    Status = request.Status,
                    MainUserId = "",
                    AppId = 0,
                    AppName = "",
                    RoleId = "",
                    RoleName = "",
                    Claims = request.Claims,
                    CreatedDate = DateTime.MinValue
                };

                var isValidOldPassword = false;

                var result = await _userIdentityService.UpdateAspNetUsers(userRequest, request.OldPassword);

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

        [HttpPatch("account/unlock/{userId}")]
        public async Task<IActionResult> UnlockAccount(long userId, [FromQuery(Name = "is-unlocked")] bool isUnlocked)
        {
            var result = isUnlocked ? await _userIdentityService.UnlockAccount(userId) : await _userIdentityService.LockAccount(userId);

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

        [HttpGet("")]
        public async Task<IActionResult> GetUser([FromQuery] string id)
        {
            try
            {
                var result = await _userIdentityService.GetCurrentUser(id);

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

        [HttpPost("list")]
        public async Task<IActionResult> GetManageUserList([FromBody] UserGroupRequest user, [FromQuery] bool isShowSuperAdmin = false)
        {
            try
            {
                var result = await _userIdentityService.GetAspNetRoleUsers(user, isShowSuperAdmin);

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
        public async Task<IActionResult> GetPermissionList([FromQuery] bool isSubUserOnly, [FromQuery] string? categories = "")
        {
            try
            {
                var version = 0;
                if (HttpContext.Request.Headers.ContainsKey("x-verion"))
                {
                    int.TryParse(HttpContext.Request.Headers["x-verion"].ToString(), out version);
                }

                var result = new BaseResponse<PermissionResponse>();
                if (!string.IsNullOrWhiteSpace(categories))
                    result = await _authRepository.GetPermissionList(isSubUserOnly, version, categories);
                else
                    result = await _authRepository.GetPermissionList(isSubUserOnly, version);

                switch (result.StatusCode)
                {
                    case AuthStatusCode.Success:
                        return Ok(result);
                    default:
                        return BadRequest(result);
                }
            }
            catch (Exception ex)
            {
                return BadRequest(null);
            }
        }

        [HttpGet("usergroup")]
        public async Task<IActionResult> GetUserGroup([FromQuery] string? id = "", long? userGroupIdRef = 0)
        {
            var result = await _userIdentityService.GetAspNetRoles(id, userGroupIdRef.HasValue ? userGroupIdRef.Value : 0);

            switch (result.StatusCode)
            {
                case AuthStatusCode.Success:
                    return Ok(result);
                default:
                    return BadRequest(result);
            }
        }

        [HttpPost("usergroup/list")]
        public async Task<IActionResult> GetUserGroupList([FromBody] UserGroupListRequest? request = null)
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

        [HttpPost("activitylog/list/{userId}")]
        public async Task<IActionResult> GetActivityLogList([FromRoute] string userId, [FromBody] MetaData metaData, [FromQuery] string? search = "")
        {
            try
            {
                var result = await _authRepository.GetActivityLogList(userId, search, metaData);

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

        [HttpPost("report/roles/url")]
        public async Task<IActionResult> GetReportRolesUrl([FromBody] ReportRolesUrlRequest request)
        {
            try
            {
                var result = await _userIdentityService.GetReportRolesUrl(request);

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
