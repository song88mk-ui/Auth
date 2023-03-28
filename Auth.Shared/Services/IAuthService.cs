using Auth.Shared.Enums;
using Auth.Shared.Models;
using Auth.Shared.Models.Request;
using Auth.Shared.Models.Response;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Auth.Api.Services
{
    public interface IAuthService
    {
        Task<BaseResponse<long>> AddAspNetUsers(UserRegisterRequest request);
        Task<BaseResponse<bool>> UpdateAspNetUsers(UserRegisterRequest request, bool isDefault = false);
        Task<BaseResponse<bool>> UpdateAspNetUserRole(UserRegisterRequest request);
        Task<BaseResponse<bool?>> UnlockAccount(long userId);
        Task<BaseResponse<bool?>> LockAccount(long userId);
        Task<bool> ModifyAspNetUserClaims(string userId, List<string> settings);
        Task<List<string>> GetAspNetUserClaims(string userId);
        Task<BaseResponse<UserListResponse>> GetAspNetSubAccountList(SubAccountListRequest request);
        Task<BaseResponse<UserGroupResponse>> GetAspNetRoles(string roleId, long userGroupIdRef);
        Task<BaseResponse<UserGroupListResponse>> GetAspNetRolesList(UserGroupListRequest request);
        Task<RoleModel> GetAspNetUsersRole(AppUser user);
        Task<BaseResponse<UserListResponse>> GetAspNetRoleUsers(UserGroupRequest request, bool isShowSuperAdmin = false);
        Task<string> GetAspNetUsersRoleId(string userid);
        Task<List<ClaimModel>> GetAspNetRoleClaims(string roleId);
        Task<List<ClaimModel>> GetAspNetRoleClaimsByName(string roleName);
        Task<List<RoleModel>> GetAspNetRole();
        Task<BaseResponse<UserGroupResponse>> AddOrUpdateAspNetRoles(UserGroupRequest request);
        Task<BaseResponse<bool>> DeleteAspNetRoles(UserGroupRequest request);
        Task<BaseResponse<AppUser>> GetCurrentUser(ClaimsPrincipal principal);
        Task<BaseResponse<IdentityRole>> GetCurrentUserRole(AppUser user);
        Task<RoleModel> GetAspNetRoleByName(string name);
        Task<BaseResponse<UserResponse>> GetCurrentUser(string userId);
        Task<BaseResponse<bool>> SetNickname(string userId, string nickname);
        Task<BaseResponse<ReportRolesUrlResponse>> GetReportRolesUrl(ReportRolesUrlRequest request);
    }
}
