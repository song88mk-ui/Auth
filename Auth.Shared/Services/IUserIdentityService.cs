using Auth.Shared.Enums;
using Auth.Shared.Models;
using Auth.Shared.Models.Request;
using Auth.Shared.Models.Response;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Auth.Api.Services
{
    public interface IUserIdentityService
    {
        Task<BaseResponse<bool>> AddAspNetUsers(UserRegisterRequest request);
        Task<BaseResponse<bool>> UpdateAspNetUsers(UserRegisterRequest request, bool isDefault = false);
        Task<BaseResponse<bool>> UpdateAspNetUserRole(UserRegisterRequest request);
        Task<BaseResponse<bool>> ChangePasswordAspNetUsers(AppUser request);
        Task<bool> ModifyAspNetUserClaims(string userId, List<string> settings);
        Task<List<string>> GetAspNetUserClaims(string userId);
        Task<BaseResponse<UserListResponse>> GetAspNetSubAccountList(SubAccountListRequest request);
        Task<BaseResponse<UserGroupListResponse>> GetAspNetRolesList(UserGroupListRequest request);
        Task<AppRole> GetAspNetUsersRole(AppUser user);
        Task<BaseResponse<UserListResponse>> GetAspNetRoleUsers(UserGroupRequest request, bool isShowSuperAdmin = false);
        Task<string> GetAspNetUsersRoleId(string userid);
        Task<List<ClaimModel>> GetAspNetRoleClaims(string roleId);
        Task<List<ClaimModel>> GetAspNetRoleClaimsByName(string roleName);
        Task<List<AppRole>> GetAspNetRole();
        Task<BaseResponse<UserGroupResponse>> AddOrUpdateAspNetRoles(UserGroupRequest request);
        Task<BaseResponse<bool>> DeleteAspNetRoles(UserGroupRequest request);
        Task<BaseResponse<AppUser>> GetCurrentUser(ClaimsPrincipal principal);
        Task<BaseResponse<IdentityRole>> GetCurrentUserRole(AppUser user);
        Task<AppRole> GetAspNetRoleByName(string name);
        Task<BaseResponse<UserResponse>> GetCurrentUser(string userId);
        Task<BaseResponse<bool>> ChangePassword(AppUser user, string currentPassword, string newPassword);
        Task<BaseResponse<ReportRolesUrlResponse>> GetReportRolesUrl(ReportRolesUrlRequest request);
    }
}
