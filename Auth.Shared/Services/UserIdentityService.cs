using Auth.Shared.Data.Auth;
using Auth.Shared.Enums;
using Auth.Shared.Models;
using Auth.Shared.Models.Request;
using Auth.Shared.Models.Response;
using Auth.Shared.Utilities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking.Internal;
using System.Security.Claims;
using System.Transactions;

namespace Auth.Api.Services
{
    public class UserIdentityService : IUserIdentityService, IDisposable
    {
        #region Fields
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserIdentityContext _userIdentityContext;
        private readonly IMemCache _memCache;
        private AuthContext _authContext { get; set; }
        #endregion

        #region Ctor
        public UserIdentityService(AuthContext authContext, UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, UserIdentityContext userIdentityContext, IMemCache memCache)
        {
            _authContext = authContext;
            _userManager = userManager;
            _roleManager = roleManager;
            _userIdentityContext = userIdentityContext;
            _memCache = memCache;
        }
        #endregion

        #region Methods
        public async Task<BaseResponse<UserListResponse>> GetAspNetSubAccountList(SubAccountListRequest request)
        {
            try
            {
                var accounts = _userManager.Users.AsNoTracking().Where(u => u.MainUserId == request.MainUserId && (string.IsNullOrEmpty(request.SearchText) || u.UserName.Contains(request.SearchText) || u.NickName.Contains(request.SearchText))).ToList();

                var permissions = (await GetPermissionList(false)).Result.Permissions ?? new List<PermissionModel>();

                var users = new List<AppUser>();
                var metaData = new MetaData();
                if (request.Page > 0 && request.PageSize > 0)
                {
                    var rowCount = accounts.Count();
                    var skip = (request.Page - 1) * request.PageSize;
                    var totalPage = ((rowCount - 1) / request.PageSize) + 1;

                    users = accounts.Skip(skip).Take(request.PageSize).ToList();

                    metaData = new MetaData
                    {
                        TotalCount = rowCount,
                        CurrentPage = request.Page,
                        PageSize = request.PageSize,
                        TotalPages = totalPage
                    };
                }

                var response = new List<UserResponse>();
                if (users.Any())
                {
                    foreach (var s in users)
                    {
                        var claimsModel = new List<ClaimModel>();
                        if (s != null)
                        {
                            var userClaim = await _userManager.GetClaimsAsync(s);
                            var result = userClaim.Join(permissions, claims => claims.Type.ToLower(), permission => permission.Id.ToLower(), (claims, permission) => new { Claims = claims, Permission = permission })
                                     .Select(p => new ClaimModel
                                     {
                                         ClaimType = p.Permission.ClaimType,
                                         ClaimValue = p.Claims.Value
                                     }).ToList();

                            claimsModel = result == null ? new List<ClaimModel>() : result;
                        }

                        var userResponse = new UserResponse
                        {
                            UserId = s.Id,
                            NickName = s.NickName,
                            UserName = s.UserName,
                            Email = s.Email,
                            CreatedDate = s.CreatedDate,
                            AppId = s.AppId,
                            AppName = s.AppName,
                            MainUserId = s.MainUserId,
                            Status = s.LockoutEnd != null ? "Locked" : "Normal",
                            Claims = claimsModel
                        };
                        response.Add(userResponse);

                    }
                }

                return new BaseResponse<UserListResponse>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = new UserListResponse
                    {
                        Users = response,
                        MetaData = metaData
                    }
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<UserListResponse>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})",
                    Result = new UserListResponse()
                };
            }

        }
        public async Task<BaseResponse<UserGroupListResponse>> GetAspNetRolesList(UserGroupListRequest request)
        {
            try
            {
                var query = _roleManager.Roles.AsNoTracking().ToList();

                if (!string.IsNullOrEmpty(request.SearchText))
                    query = query.Where(result => result.Name.Contains(request.SearchText)).ToList();

                if (!request.ShowSuperAdmin)
                    query = query.Where(c => c.Name.ToLower() != "super admin").ToList();

                var rowCount = query.Count();
                var skip = request.PageSize == -1 ? 0 : (request.Page - 1) * request.PageSize;
                var totalPage = request.PageSize == -1 ? 0 : ((rowCount - 1) / request.PageSize) + 1;

                var roles = query.Skip(skip).Take(request.PageSize == -1 ? rowCount : request.PageSize).ToList();

                var result = new UserGroupListResponse();

                foreach (var role in roles)
                {
                    var userCount = (await _userManager.GetUsersInRoleAsync(role.Name)).Count;

                    var claims = await GetAspNetRoleClaims(role.Id);

                    result.UserGroups.Add(new UserGroupResponse
                    {
                        UserGroupId = role.Id,
                        UserGroupName = role.Name,
                        Claims = claims ?? new List<ClaimModel>()
                    });
                }

                result.MetaData = new MetaData
                {
                    TotalCount = rowCount,
                    CurrentPage = request.Page,
                    PageSize = request.PageSize,
                    TotalPages = totalPage
                };

                return new BaseResponse<UserGroupListResponse>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = result ?? new UserGroupListResponse()
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<UserGroupListResponse>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }

        }

        public async Task<bool> ModifyAspNetUserClaims(string userId, List<string> settings)
        {
            try
            {
                var userClaims = _userIdentityContext.UserClaims.AsNoTracking().Where(c => c.UserId == userId);
                _userIdentityContext.UserClaims.RemoveRange(userClaims);

                var newSettings = new List<IdentityUserClaim<string>>();
                foreach (var item in settings)
                {
                    newSettings.Add(new IdentityUserClaim<string>()
                    {
                        UserId = userId,
                        ClaimType = item
                    });

                }

                if (newSettings.Any())
                    await _userIdentityContext.UserClaims.AddRangeAsync(newSettings);

                return true;
            }
            catch (Exception)
            {
                return false;
            };
        }

        public async Task<List<string>> GetAspNetUserClaims(string userId)
        {
            try
            {
                var result = new List<string>();
                var userClaims = _userIdentityContext.UserClaims.AsNoTracking().Where(c => c.UserId == userId).ToList();

                if (userClaims != null)
                {
                    foreach (var item in userClaims.Select(c => c.ClaimValue))
                    {
                        result.Add(item);
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                return null;
            }

        }
        public async Task<AppRole> GetAspNetUsersRole(AppUser request)
        {
            try
            {
                var userRole = _userIdentityContext.UserRoles.FirstOrDefault(c => c.UserId == request.Id)?.RoleId;
                var role = _roleManager.Roles.FirstOrDefault(c => c.Id == userRole);

                if (role != null)
                {
                    return new AppRole
                    {
                        Id = role.Id,
                        Name = role.Name
                    };
                }

                return new AppRole();
            }
            catch (Exception ex)
            {
                return null;
            }

        }
        public async Task<BaseResponse<UserListResponse>> GetAspNetRoleUsers(UserGroupRequest request, bool isShowSuperAdmin = false)
        {
            try
            {
                var users = GetUserList(request.Selection, request.SearchText, request.SortBy, isShowSuperAdmin);

                var result = new UserListResponse();
                if (users.Any())
                {
                    var userGroups = _userIdentityContext.UserRoles.Join(_userIdentityContext.Roles,
                                     userRole => userRole.RoleId,
                                     role => role.Id,
                                     (userRole, role) => new { userRole.UserId, role.Id, role.Name, role.NormalizedName }).ToList();

                    result.Users = users.Join(userGroups,
                               user => user.Id,
                               userGroup => userGroup.UserId,
                               (users, userGroups) => new UserResponse()
                               {
                                   UserId = users.Id,
                                   NickName = users.NickName,
                                   UserName = users.UserName,
                                   Password = users.PasswordHash,
                                   Email = users.Email,
                                   CreatedDate = users.CreatedDate,
                                   AppId = users.AppId,
                                   AppName = users.AppName,
                                   MainUserId = users.MainUserId,
                                   Status = users.LockoutEnd != null ? "Locked" : "Normal",
                                   RoleId = userGroups.Id,
                                   RoleName = userGroups.Name,
                               }).ToList();
                    if (!string.IsNullOrWhiteSpace(request.UserGroupId))
                        result.Users = result.Users.Where(x => x.RoleId == request.UserGroupId).ToList();

                    var rowCount = result.Users.Count();
                    if (request.MetaData.PageSize == 0)
                        request.MetaData.PageSize = rowCount;

                    var skip = request.MetaData == null ? 0 : (request.MetaData.CurrentPage - 1) * request.MetaData.PageSize;
                    var totalPage = request.MetaData == null ? 0 : ((rowCount - 1) / request.MetaData.PageSize) + 1;


                    result.Users = result.Users.Skip(skip).Take(request.MetaData == null ? rowCount : request.MetaData.PageSize).ToList();

                    request.MetaData = new MetaData
                    {
                        TotalCount = rowCount,
                        CurrentPage = request.MetaData.CurrentPage,
                        PageSize = request.MetaData.PageSize,
                        TotalPages = totalPage
                    };
                    result.MetaData = request.MetaData;
                }

                return new BaseResponse<UserListResponse>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = result ?? new UserListResponse()
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<UserListResponse>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }

        }
        public async Task<string> GetAspNetUsersRoleId(string userid)
        {
            try
            {
                var roleId = _userIdentityContext.UserRoles.Where(x => x.UserId == userid);
                return roleId.FirstOrDefault().RoleId;
            }
            catch (Exception ex)
            {
                return null;
            }

        }
        public async Task<List<AppRole>> GetAspNetRole()
        {
            try
            {
                var appRoleList = new List<AppRole>();
                var result = _roleManager.Roles.Select(x => new { x.Id, x.Name, x.NormalizedName, x.ConcurrencyStamp });

                foreach (var tmprole in result)
                {
                    var role = new AppRole
                    {
                        Id = tmprole.Id,
                        Name = tmprole.Name,
                        NormalizedName = tmprole.NormalizedName,
                        ConcurrencyStamp = tmprole.ConcurrencyStamp
                    };

                    appRoleList.Add(role);
                }

                return appRoleList;
            }
            catch (Exception ex)
            {
                return null;
            }

        }
        public async Task<List<ClaimModel>> GetAspNetRoleClaims(string roleId)
        {
            try
            {
                var role = await _roleManager.FindByIdAsync(roleId);
                var result = await _roleManager.GetClaimsAsync(role);
                var permissions = (await GetPermissionList(false)).Result.Permissions ?? new List<PermissionModel>();

                return result.Join(permissions, claims => claims.Type.ToLower(), permission => permission.Id.ToLower(), (claims, permission) => new { Claims = claims, Permission = permission })
                        .Select(p => new ClaimModel
                        {
                            ClaimType = p.Permission.ClaimType,
                            ClaimValue = p.Claims.Value
                        }).ToList();
            }
            catch (Exception ex)
            {
                return null;
            }

        }
        public async Task<List<ClaimModel>> GetAspNetRoleClaimsByName(string roleName)
        {
            try
            {
                var role = await _roleManager.FindByNameAsync(roleName);
                var result = await _roleManager.GetClaimsAsync(role);

                return result.Select(s => new ClaimModel
                {
                    ClaimType = s.Type,
                    ClaimValue = s.Value
                }).ToList();
            }
            catch (Exception ex)
            {
                return null;
            }

        }

        public async Task<BaseResponse<bool>> AddAspNetUsers(UserRegisterRequest request)
        {
            try
            {
                var user = new AppUser
                {
                    UserName = request.UserName,
                    Email = request.Email,
                    EmailConfirmed = true,
                    CreatedDate = DateTime.UtcNow,
                    MainUserId = request.MainUserId,
                    AppId = request.AppId,
                    AppName = request.AppName,
                    NickName = request.NickName
                };

                user.LockoutEnd = null;
                if (request.Status.ToUpper() == "Locked".ToUpper())
                    user.LockoutEnd = DateTime.UtcNow;

                //var isvalid = await _userManager.UserValidators(request);
                IdentityResult result = await _userManager.CreateAsync(user, request.Password);
                if (result.Succeeded)
                {
                    var addRole = await _userManager.AddToRoleAsync(user, request.RoleName);

                    if (user.MainUserId != null)
                        if (!string.IsNullOrWhiteSpace(user.MainUserId))
                        {
                            var claims = new List<Claim>();
                            if (request.Claims != null && request.Claims.Any())
                            {
                                claims = request.Claims.Select(s => new Claim(s.ClaimType, s.ClaimValue)).ToList();
                                await _userManager.AddClaimsAsync(user, claims);
                            }
                        }

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = true
                    };
                }
                else
                {
                    string errorMsg = "";
                    foreach (IdentityError error in result.Errors)
                        errorMsg += error.Description.ToString() + ",";

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Error,
                        Message = $"{errorMsg.TrimEnd(',')} "
                    };
                }
            }
            catch (Exception ex)
            {
                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }
        public async Task<BaseResponse<bool>> UpdateAspNetUsers(UserRegisterRequest request, bool isDefault = false)
        {
            try
            {
                var user = (await _userManager.FindByIdAsync(request.UserId));
                if (!isDefault)
                {
                    user.Email = request.Email;
                    user.EmailConfirmed = true;
                }

                if (request.Status.ToUpper() == "Locked".ToUpper() && user.LockoutEnd == null)
                    user.LockoutEnd = DateTime.UtcNow;
                else
                    user.LockoutEnd = null;

                user.NickName = request.NickName;

                if (!string.IsNullOrWhiteSpace(request.Password))
                {
                    user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, request.Password);
                }

                var oldRoles = await _userManager.GetRolesAsync(user);
                var removeRoles = await _userManager.RemoveFromRolesAsync(user, oldRoles);
                var addRole = await _userManager.AddToRoleAsync(user, request.RoleName);

                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    if (user.MainUserId != null)
                        if (!string.IsNullOrWhiteSpace(user.MainUserId))
                        {
                            var oldClaims = await _userManager.GetClaimsAsync(user);
                            var removeClaims = await _userManager.RemoveClaimsAsync(user, oldClaims);

                            var claims = new List<Claim>();
                            if (request.Claims != null && request.Claims.Any())
                            {
                                claims = request.Claims.Select(s => new Claim(s.ClaimType, s.ClaimValue)).ToList();
                                await _userManager.AddClaimsAsync(user, claims);
                            }
                        }

                    if (!string.IsNullOrEmpty(request.Password))
                    {
                        user.PasswordHash = request.Password;

                        await ChangePasswordAspNetUsers(user);
                    }

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = true
                    };
                }
                else
                {
                    string errorMsg = "";
                    foreach (IdentityError error in result.Errors)
                        errorMsg += error.Description.ToString() + ",";

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Error,
                        Message = $"{errorMsg.TrimEnd(',')} "
                    };
                }

            }
            catch (Exception ex)
            {
                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }
        public async Task<BaseResponse<bool>> UpdateAspNetUserRole(UserRegisterRequest request)
        {
            try
            {
                var user = (await _userManager.FindByIdAsync(request.UserId));

                var oldRoles = await _userManager.GetRolesAsync(user);
                var removeRoles = await _userManager.RemoveFromRolesAsync(user, oldRoles);
                var addRole = await _userManager.AddToRoleAsync(user, request.RoleName);

                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    var oldClaims = await _userManager.GetClaimsAsync(user);
                    var removeClaims = await _userManager.RemoveClaimsAsync(user, oldClaims);

                    var claims = new List<Claim>();
                    if (request.Claims != null && request.Claims.Any())
                    {
                        claims = request.Claims.Select(s => new Claim(s.ClaimType, s.ClaimValue)).ToList();
                        await _userManager.AddClaimsAsync(user, claims);
                    }

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = true
                    };
                }
                else
                {
                    string errorMsg = "";
                    foreach (IdentityError error in result.Errors)
                        errorMsg += error.Description.ToString() + ",";

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Error,
                        Message = $"{errorMsg.TrimEnd(',')} "
                    };
                }

            }
            catch (Exception ex)
            {
                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }

        public async Task<BaseResponse<bool>> ChangePasswordAspNetUsers(AppUser request)
        {
            try
            {
                var user = _userManager.FindByIdAsync(request.Id).Result;

                if (request.PasswordHash != null)
                {
                    var passwordValidator = new PasswordValidator<AppUser>();
                    var isValid = await passwordValidator.ValidateAsync(_userManager, null, request.PasswordHash);

                    if (isValid.Succeeded)
                    {
                        user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, request.PasswordHash);
                    }
                    else
                    {
                        var errorMsg = string.Empty;

                        foreach (var error in isValid.Errors)
                        {
                            errorMsg += $"{error.Description},";
                        }

                        return new BaseResponse<bool>
                        {
                            StatusCode = StatusCode.Error,
                            Message = $"{errorMsg.TrimEnd(',')}"
                        };
                    }
                }

                IdentityResult result = await _userManager.UpdateAsync(user);
                if (result.Succeeded)
                {
                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = true
                    };
                }

                else
                {
                    string errorMsg = "";
                    foreach (IdentityError error in result.Errors)
                        errorMsg += error.Description.ToString() + ",";

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Error,
                        Message = $"{errorMsg.TrimEnd(',')} "
                    };
                }

            }
            catch (Exception ex)
            {
                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }
        public async Task<BaseResponse<UserGroupResponse>> AddOrUpdateAspNetRoles(UserGroupRequest request)
        {
            try
            {
                IdentityResult result = new IdentityResult();
                //List<AppRoleClaim> tmpRoleClaims
                var appRole = await _roleManager.FindByIdAsync(request.UserGroupId);

                if (appRole == null)
                {
                    result = await _roleManager.CreateAsync(new IdentityRole(request.UserGroupName));
                    appRole = await _roleManager.FindByNameAsync(request.UserGroupName);

                    request.UserGroupId = appRole.Id;
                }
                else
                {
                    appRole.Name = request.UserGroupName;
                    result = await _roleManager.UpdateAsync(appRole);
                }

                if (result.Succeeded)
                {
                    using (var scope = new TransactionScope(TransactionScopeOption.Required, new System.Transactions.TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }, TransactionScopeAsyncFlowOption.Enabled))
                    {
                        foreach (var claims in request.Claims)
                        {
                            var newClaims = _userIdentityContext.RoleClaims.FirstOrDefault(x => x.RoleId == request.UserGroupId && x.ClaimType == claims.ClaimType);
                            if (newClaims == null)
                            {
                                Claim newClaims2 = new Claim(claims.ClaimType, claims.ClaimValue);
                                await _roleManager.AddClaimAsync(appRole, newClaims2);
                            }
                            else
                            {
                                newClaims.ClaimValue = claims.ClaimValue;
                                _userIdentityContext.RoleClaims.Update(newClaims);

                                await _userIdentityContext.SaveChangesAsync();

                                _userIdentityContext.Entry(newClaims).State = EntityState.Detached;
                            }
                        }


                        scope.Complete();

                    }

                    return new BaseResponse<UserGroupResponse>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = new UserGroupResponse
                        {
                            UserGroupId = appRole.Id,
                            UserGroupName = appRole.Name,
                            Claims = request.Claims
                        }
                    };
                }
                else
                {
                    string errorMsg = "";
                    foreach (IdentityError error in result.Errors)
                        errorMsg += error.Description.ToString() + ",";

                    return new BaseResponse<UserGroupResponse>
                    {
                        StatusCode = StatusCode.Error,
                        Message = $"{errorMsg.TrimEnd(',')} "
                    };
                }

            }
            catch (Exception ex)
            {
                return new BaseResponse<UserGroupResponse>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }

        public async Task<BaseResponse<bool>> DeleteAspNetRoles(UserGroupRequest request)
        {
            try
            {
                var appRole = await _roleManager.FindByIdAsync(request.UserGroupId);
                var appUsers = (await GetAspNetRoleUsers(request)).Result.Users;

                foreach (var user in appUsers)
                {
                    var claims = await GetAspNetRoleClaimsByName("Default");

                    var userRequest = new UserRegisterRequest
                    {
                        UserId = user.UserId,
                        UserName = user.UserName,
                        Email = user.Email,
                        AppId = user.AppId,
                        AppName = user.AppName,
                        RoleName = "Default",
                        Claims = claims ?? new List<ClaimModel>()
                    };

                    var addResult = await UpdateAspNetUserRole(userRequest);
                }

                IdentityResult result = await _roleManager.DeleteAsync(appRole);

                if (result.Succeeded)
                {
                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = true
                    };
                }

                else
                {
                    string errorMsg = "";
                    foreach (IdentityError error in result.Errors)
                        errorMsg += error.Description.ToString() + ",";

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Error,
                        Message = $"{errorMsg.TrimEnd(',')} "
                    };
                }


            }
            catch (Exception ex)
            {
                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }

        public async Task<BaseResponse<AppUser>> GetCurrentUser(ClaimsPrincipal principal)
        {
            try
            {
                var user = await _userManager.GetUserAsync(principal);

                return new BaseResponse<AppUser>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = user
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<AppUser>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }
        public async Task<BaseResponse<IdentityRole>> GetCurrentUserRole(AppUser user)
        {
            try
            {
                var roleName = _userManager.GetRolesAsync(user).Result.FirstOrDefault();
                var role = _roleManager.FindByNameAsync(roleName).Result;

                return new BaseResponse<IdentityRole>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = role
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<IdentityRole>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }
        public async Task<AppRole> GetAspNetRoleByName(string name)
        {
            try
            {
                var role = _roleManager.Roles.AsNoTracking().FirstOrDefault(c => c.Name == name);
                var userCount = (await _userManager.GetUsersInRoleAsync(role.Name)).Count;

                return new AppRole
                {
                    Id = role.Id,
                    Name = role.Name,
                    NormalizedName = role.NormalizedName,
                    ConcurrencyStamp = role.ConcurrencyStamp,
                    UserCount = userCount
                };
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public async Task<BaseResponse<UserResponse>> GetCurrentUser(string userId)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                var claimsModel = new List<ClaimModel>();
                if (user != null)
                {
                    var userClaim = await _userManager.GetClaimsAsync(user);
                    claimsModel = userClaim == null ? new List<ClaimModel>() : userClaim.Select(s => new ClaimModel { ClaimType = s.Type, ClaimValue = s.Value }).ToList();
                }

                return new BaseResponse<UserResponse>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = user == null ? new UserResponse() : new UserResponse
                    {
                        UserId = user.Id,
                        NickName = user.NickName,
                        UserName = user.UserName,
                        Email = user.Email,
                        CreatedDate = user.CreatedDate,
                        AppId = user.AppId,
                        AppName = user.AppName,
                        MainUserId = user.MainUserId,
                        Status = user.LockoutEnd != null ? "Locked" : "Normal",
                        Claims = claimsModel
                    }
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<UserResponse>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }
        public async Task<BaseResponse<bool>> ChangePassword(AppUser user, string currentPassword, string newPassword)
        {
            try
            {
                var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);

                if (result.Succeeded)
                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = true
                    };
                else
                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Error,
                        Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({result})"
                    };
            }
            catch (Exception ex)
            {
                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }

        public async Task<BaseResponse<ReportRolesUrlResponse>> GetReportRolesUrl(ReportRolesUrlRequest request)
        {
            var mKey = $"rru:{request.RoleId}:{request.ClaimType}";

            var mCache = _memCache.GetCache<BaseResponse<ReportRolesUrlResponse>>(mKey);

            if (mCache != null)
                return mCache;

            try
            {
                var response = new BaseResponse<ReportRolesUrlResponse>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = new ReportRolesUrlResponse
                    {
                        RoleId = request.RoleId,
                        ClaimType = request.ClaimType
                    }
                };

                var result = _authContext.ReportRoles.FirstOrDefault(r => r.RoleId == request.RoleId && r.ClaimType == request.ClaimType);

                var role = await _roleManager.FindByIdAsync(request.RoleId);

                if (result != null && role != null)
                {
                    response.Result.RoleName = role.Name;
                    response.Result.Url = result.Url;

                    _memCache.AddOrUpdateCache(mKey, response, DateTimeOffset.UtcNow.AddHours(24));
                }

                return response;
            }
            catch (Exception ex)
            {
                return new BaseResponse<ReportRolesUrlResponse>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }

        public void Dispose()
        {
            _roleManager.Dispose();
            _userManager.Dispose();
        }

        #endregion

        #region Utilities

        private List<AppUser> GetUserList(string selection, string search = "", UserSorting sortBy = UserSorting.SortByCreateDateDesc, bool isShowSuperAdmin = false)
        {
            var users = new List<AppUser>();
            search = search.ToLower();

            if (!string.IsNullOrWhiteSpace(selection.Trim()))
            {
                users = _userManager.Users.AsNoTracking().Where(x => (x.MainUserId.ToLower() == selection.ToLower()) &&
                        (string.IsNullOrWhiteSpace(search) ||
                        x.UserName.ToLower().Contains(search) ||
                        (x.NickName != null && x.NickName.ToLower().Contains(search)) ||
                        x.Email.ToLower().Contains(search))).ToList();
            }
            else
            {
                users = _userManager.Users.AsNoTracking().Where(x => string.IsNullOrWhiteSpace(x.MainUserId) &&
                        (string.IsNullOrWhiteSpace(search) ||
                        x.UserName.ToLower().Contains(search) ||
                        (x.NickName != null && x.NickName.ToLower().Contains(search)) ||
                        x.Email.ToLower().Contains(search))).ToList();
            }

            if (!isShowSuperAdmin)
            {
                var superAdmin = _roleManager.Roles.AsNoTracking().Where(x => x.Name.Trim().ToUpper() == "SUPERADMIN").FirstOrDefault()?.Id ?? "";
                users = users.
                    Join(_userIdentityContext.UserRoles, user => user.Id, userRole => userRole.UserId, (user, userRole) => new { user, userRole.RoleId })
                    .Where(x => x.RoleId != superAdmin)
                    .Select(x => x.user).ToList();
            }

            if (!isShowSuperAdmin)
                users.Remove(users.Where(x => x.UserName == "fci-admin").FirstOrDefault());

            if (users.Any())
            {
                switch ((int)sortBy)
                {
                    case 0:
                        users = users.OrderBy(x => x.UserName).ToList();
                        break;
                    case 1:
                        users = users.OrderByDescending(x => x.UserName).ToList();
                        break;
                    case 2:
                        users = users.OrderBy(x => x.CreatedDate).ToList();
                        break;
                    default:
                        users = users.OrderByDescending(x => x.CreatedDate).ToList();
                        break;
                }
            }

            return users;
        }
        public async Task<BaseResponse<PermissionResponse>> GetPermissionList(bool isSubUserOnly)
        {
            var result = await _authContext.Permission.Where(p => isSubUserOnly == false || p.IsSubUser == isSubUserOnly).ToListAsync();

            var permList = result.Select(a => new PermissionModel()
            {
                Id = a.PermissionId.ToString(),
                CategoryId = a.CategoryId,
                CategoryName = a.CategoryName,
                SubCategoryName = a.SubCategoryName,
                GroupName = a.GroupName,
                Name = a.Name,
                ClaimType = a.ClaimType,
                HasReadOnly = a.HasReadOnly,
                SortOrder = a.SortOrder,
                IsSubUser = a.IsSubUser
            }).OrderBy(x => x.CategoryName).ThenBy(o => o.SortOrder).ToList();

            return new BaseResponse<PermissionResponse>
            {
                StatusCode = StatusCode.Success,
                Message = StatusCode.Success.ToString(),
                Result = new PermissionResponse()
                {
                    Permissions = permList
                }
            };
        }
        #endregion
    }
}