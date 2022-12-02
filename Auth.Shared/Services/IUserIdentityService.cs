using Auth.Shared.Models;
using Auth.Shared.Models.Request;
using Auth.Shared.Models.Response;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Auth.Api.Services
{
    public interface IUserIdentityService
    {
        Task<BaseResponse<bool>> AddAspNetUsers(UserComposeRequest request);
        Task<BaseResponse<bool>> UpdateAspNetUsers(UserComposeRequest request, bool isDefault = false);
        Task<BaseResponse<bool>> ChangePasswordAspNetUsers(AppUser request);
        Task<bool> ModifyAspNetUserClaims(string userId, List<string> settings);
        Task<List<string>> GetAspNetUserClaims(string userId);
        Task<BaseResponse<UserListResponse>> GetAspNetUsersList(string search = "", bool showSuperAdmin = false);
        Task<BaseResponse<UserListResponse>> GetAspNetSubAccountList(SubAccountListRequest request);
        Task<List<AppRole>> GetAspNetRolesList(string search = "", bool showSuperAdmin = false);
        Task<AppRole> GetAspNetUsersRole(AppUser user);
        Task<List<AppUser>> GetAspNetRoleUsers(string roleId);
        Task<string> GetAspNetUsersRoleId(string userid);
        Task<List<Claim>> GetAspNetRoleClaims(string roleId);
        Task<List<Claim>> GetAspNetRoleClaimsByName(string roleName);
        Task<List<IdentityRoleClaim<string>>> GetAspNetRoleClaims2(string roleId);
        Task<List<AppRole>> GetAspNetRole();
        Task<BaseResponse<bool>> AddAspNetRoles(string roleName, List<AppRoleClaim> tmpRoleClaims);
        Task<BaseResponse<bool>> UpdateAspNetRoles(AppRole request, List<AppRoleClaim> tmpRoleClaims);
        Task<BaseResponse<bool>> DeleteAspNetRoles(AppRole request);
        Task<BaseResponse<AppUser>> GetCurrentUser(ClaimsPrincipal principal);
        Task<BaseResponse<IdentityRole>> GetCurrentUserRole(AppUser user);
        Task<AppRole> GetAspNetRoleByName(string name);
        Task<BaseResponse<AppUser>> GetCurrentUser(string userId);
        Task<BaseResponse<bool>> ChangePassword(AppUser user, string currentPassword, string newPassword);
    }
}
