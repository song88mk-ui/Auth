using Auth.Shared.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Auth.Api.Services
{
    public interface IUserIdentityService
    {
        Task<BaseResponse<bool>> AddAspNetUsers(AppUser request, string roleName);
        Task<BaseResponse<bool>> UpdateAspNetUsers(AppUser request, string roleName, bool isDefault = false);
        Task<BaseResponse<bool>> ChangePasswordAspNetUsers(AppUser request);
        Task<bool> ModifyAspNetUserClaims(string userId, List<string> settings);
        Task<List<string>> GetAspNetUserClaims(string userId);
        Task<List<IdentityUser>> GetAspNetUsersList(string search = "", bool showSuperAdmin = false);
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
        Task<BaseResponse<IdentityUser>> GetCurrentUser(ClaimsPrincipal principal);
        Task<BaseResponse<IdentityRole>> GetCurrentUserRole(IdentityUser user);
        Task<AppRole> GetAspNetRoleByName(string name);
        Task<BaseResponse<IdentityUser>> GetCurrentUser(string userId);
        Task<BaseResponse<bool>> ChangePassword(IdentityUser user, string currentPassword, string newPassword);
    }
}
