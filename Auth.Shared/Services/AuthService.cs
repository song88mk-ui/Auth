using Auth.Shared.Data.Auth;
using Auth.Shared.Enums;
using Auth.Shared.Models;
using Auth.Shared.Models.Request;
using Auth.Shared.Models.Response;
using Auth.Shared.Utilities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking.Internal;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.Security.Claims;
using System.Transactions;

namespace Auth.Api.Services
{
    public class AuthService : IAuthService, IDisposable
    {
        #region Fields
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<AppRole> _roleManager;
        private readonly AuthContext _authContext;
        private readonly IMemCache _memCache;
        #endregion

        #region Ctor
        public AuthService(UserManager<AppUser> userManager, RoleManager<AppRole> roleManager, AuthContext authContext, IMemCache memCache)
        {
            _authContext = authContext;
            _userManager = userManager;
            _roleManager = roleManager;
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
                            UserIdRef = s.IdRef,
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
        public async Task<BaseResponse<UserGroupResponse>> GetAspNetRoles(string roleId, long userGroupIdRef)
        {
            try
            {
                var query = _roleManager.Roles.AsNoTracking();

                if (!string.IsNullOrEmpty(roleId))
                {
                    query = query.Where(c => c.Id == roleId);
                }
                else if (userGroupIdRef > 0)
                {
                    query = query.Where(c => c.UserGroupIdRef == userGroupIdRef);
                }

                var userGroup = new UserGroupResponse();

                if (!string.IsNullOrEmpty(roleId) || userGroupIdRef > 0)
                {
                    var role = query.FirstOrDefault();
                    var claims = await GetAspNetRoleClaims(role.Id);

                    userGroup = new UserGroupResponse
                    {
                        UserGroupId = role.Id,
                        UserGroupIdRef = role.UserGroupIdRef,
                        UserGroupName = role.Name,
                        Claims = claims ?? new List<ClaimModel>()
                    };
                }

                return new BaseResponse<UserGroupResponse>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = userGroup
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<UserGroupResponse>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})",
                    Result = new UserGroupResponse()
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
                        UserGroupIdRef = role.UserGroupIdRef,
                        UserGroupName = role.Name,
                        Claims = claims ?? new List<ClaimModel>(),
                        UserCount = userCount
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
                var userClaims = _authContext.UserClaims.AsNoTracking().Where(c => c.UserId == userId);
                _authContext.UserClaims.RemoveRange(userClaims);

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
                {
                    await _authContext.UserClaims.AddRangeAsync(newSettings);
                    _authContext.SaveChanges();
                }

                return true;
            }
            catch (Exception)
            {
                return false;
            }
            ;
        }

        public async Task<List<string>> GetAspNetUserClaims(string userId)
        {
            try
            {
                var result = new List<string>();
                var userClaims = _authContext.UserClaims.AsNoTracking().Where(c => c.UserId == userId).ToList();

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
        public async Task<RoleModel> GetAspNetUsersRole(AppUser request)
        {
            try
            {
                var userRole = _authContext.UserRoles.FirstOrDefault(c => c.UserId == request.Id)?.RoleId;
                var role = _roleManager.Roles.FirstOrDefault(c => c.Id == userRole);

                if (role != null)
                {
                    return new RoleModel
                    {
                        Id = role.Id,
                        Name = role.Name
                    };
                }

                return new RoleModel();
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
                    var userGroups = _authContext.UserRoles.Join(_authContext.Roles,
                                     userRole => userRole.RoleId,
                                     role => role.Id,
                                     (userRole, role) => new { userRole.UserId, role.Id, role.Name, role.NormalizedName, role.UserGroupIdRef }).ToList();

                    result.Users = users.Join(userGroups,
                               user => user.Id,
                               userGroup => userGroup.UserId,
                               (users, userGroups) => new UserResponse()
                               {
                                   UserId = users.Id,
                                   UserIdRef = users.IdRef,
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
                    {
                        var roleId = GetRoleId(request.UserGroupId);
                        result.Users = result.Users.Where(x => x.RoleId == roleId).ToList();
                    }

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
                var roleId = _authContext.UserRoles.Where(x => x.UserId == userid);
                return roleId.FirstOrDefault().RoleId;
            }
            catch (Exception ex)
            {
                return null;
            }

        }
        public async Task<List<RoleModel>> GetAspNetRole()
        {
            try
            {
                var appRoleList = new List<RoleModel>();
                var result = _roleManager.Roles.Select(x => new { x.Id, x.Name, x.NormalizedName, x.ConcurrencyStamp });

                foreach (var tmprole in result)
                {
                    var role = new RoleModel
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

        public async Task<BaseResponse<long>> AddAspNetUsers(UserRegisterRequest request)
        {
            try
            {
                long newIdRef = Convert.ToInt64(_userManager.Users.Max(u => u.IdRef) + 1);

                var user = new AppUser
                {
                    UserName = request.UserName,
                    NormalizedUserName = request.UserName.ToUpper(),
                    Email = request.Email,
                    NormalizedEmail = request.Email != null ? request.Email.ToUpper() : null,
                    IdRef = newIdRef,
                    EmailConfirmed = true,
                    CreatedDate = DateTime.UtcNow,
                    MainUserId = string.IsNullOrWhiteSpace(request.MainUserId) ? string.Empty : GetUserId(request.MainUserId),
                    AppId = request.AppId,
                    AppName = request.AppName,
                    NickName = request.NickName
                };

                user.LockoutEnd = null;
                if (request.Status.ToUpper() == "Locked".ToUpper())
                    user.LockoutEnd = DateTime.UtcNow;

                //var isvalid = await _userManager.UserValidators(request);
                user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, request.Password);
                using (var scope = new TransactionScope(TransactionScopeOption.Required, new System.Transactions.TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }, TransactionScopeAsyncFlowOption.Enabled))
                {
                    IdentityResult result = await _userManager.CreateAsync(user);
                    if (!result.Succeeded)
                    {
                        string errorMsg = "";
                        foreach (IdentityError error in result.Errors)
                            errorMsg += error.Description.ToString() + ",";
                        return new BaseResponse<long>
                        {
                            StatusCode = StatusCode.Error,
                            Message = $"{errorMsg.TrimEnd(',')} "
                        };
                    }


                    if (!string.IsNullOrEmpty(user.MainUserId) && user.MainUserId != "0")
                    {
                        var claims = new List<Claim>();
                        if (request.Claims != null && request.Claims.Any())
                        {
                            claims = request.Claims.Select(s => new Claim(s.ClaimType, s.ClaimValue)).ToList();
                            await _userManager.AddClaimsAsync(user, claims);
                        }
                    }
                    else
                    {
                        if (string.IsNullOrWhiteSpace(request.RoleId))
                        {
                            request.RoleName = "Default";
                        }

                        var addRole = await _userManager.AddToRoleAsync(user, request.RoleName);
                    }

                    _authContext.SaveChanges();
                    scope.Complete();
                }
                return new BaseResponse<long>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = newIdRef
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<long>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }
        public async Task<BaseResponse<bool>> UpdateAspNetUsers(UserRegisterRequest request, string oldPassword = "", bool isDefault = false)
        {
            try
            {
                var userId = GetUserId(request.UserId);

                var user = (await _userManager.FindByIdAsync(userId));

                AppToken userToken = null;

                if (user == null)
                {
                    return new BaseResponse<bool>()
                    {
                        StatusCode = StatusCode.Error,
                        Message = "User does not exist",
                        Result = false
                    };
                }

                if (!isDefault)
                {
                    if (!string.IsNullOrWhiteSpace(request.Email))
                    {
                        user.Email = request.Email;
                        user.EmailConfirmed = true;
                    }
                }

                if (!string.IsNullOrWhiteSpace(request.Status))
                {
                    if (request.Status.ToUpper() == "Locked".ToUpper() && user.LockoutEnd == null)
                    {
                        userToken = _authContext.UserTokens.FirstOrDefault(x => x.UserId == userId);

                        if (userToken != null)
                        {
                            _memCache.DeleteCache($"ot:{userToken.Value}");
                        }

                        user.LockoutEnd = DateTime.UtcNow;
                    }

                    if (request.Status.ToUpper() == "Normal".ToUpper() && user.LockoutEnd != null)
                        user.LockoutEnd = null;
                }

                if (!string.IsNullOrWhiteSpace(request.NickName))
                    user.NickName = request.NickName;

                var oldRoles = await _userManager.GetRolesAsync(user);

                if (!string.IsNullOrWhiteSpace(request.RoleId) && (user.MainUserId == null || string.IsNullOrEmpty(user.MainUserId)))
                {
                    var removeRoles = await _userManager.RemoveFromRolesAsync(user, oldRoles);
                    var addRole = await _userManager.AddToRoleAsync(user, request.RoleName);
                }

                var result = await _userManager.UpdateAsync(user);

                if (!result.Succeeded)
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
                    //user.PasswordHash = request.Password;

                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    if (!string.IsNullOrWhiteSpace(oldPassword))
                    {
                        var isValidOldPassword = await _userManager.CheckPasswordAsync(user, oldPassword);

                        if (isValidOldPassword)
                        {
                            if (oldPassword == request.Password)
                            {
                                return new BaseResponse<bool>
                                {
                                    StatusCode = StatusCode.Error,
                                    Message = "Sorry, you entered an old password. Please choose a password you haven't used before."
                                };
                            }
                        }

                        result = await _userManager.ChangePasswordAsync(user, oldPassword, request.Password);
                    }
                    else
                    {
                        result = await _userManager.ResetPasswordAsync(user, token, request.Password);
                    }
                }

                if (!result.Succeeded)
                {
                    string errorMsg = "";
                    foreach (IdentityError error in result.Errors)
                        errorMsg += error.Description.ToString() + ",";

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Error,
                        Message = $"{errorMsg.TrimEnd(',')}"
                    };
                }

                //force logout user                
                await ForceLogOutUsers(userId);

                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = true
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
        public async Task<BaseResponse<bool>> UpdateAspNetUserRole(UserRegisterRequest request)
        {
            try
            {
                var user = (await _userManager.FindByIdAsync(request.UserId));

                var oldRoles = await _userManager.GetRolesAsync(user);
                var removeRoles = await _userManager.RemoveFromRolesAsync(user, oldRoles);
                var addRole = await _userManager.AddToRoleAsync(user, request.RoleName);

                user.MainUserId = string.IsNullOrWhiteSpace(request.MainUserId) ? string.Empty : GetUserId(request.MainUserId);

                var result = await _userManager.UpdateAsync(user);

                if (!result.Succeeded)
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

                var oldClaims = await _userManager.GetClaimsAsync(user);
                var removeClaims = await _userManager.RemoveClaimsAsync(user, oldClaims);

                var claims = new List<Claim>();
                if (request.Claims != null && request.Claims.Any())
                {
                    claims = request.Claims.Select(s => new Claim(s.ClaimType, s.ClaimValue)).ToList();
                    await _userManager.AddClaimsAsync(user, claims);
                }

                _authContext.SaveChanges();

                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = true
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

        public async Task<BaseResponse<UserGroupResponse>> AddOrUpdateAspNetRoles(UserGroupRequest request)
        {
            try
            {
                IdentityResult result = new IdentityResult();
                var appRole = await _roleManager.FindByIdAsync(request.UserGroupId);

                if (appRole == null)
                {
                    var role = new AppRole(request.UserGroupName);

                    role.UserGroupIdRef = ConvertToEpochTimestamp(DateTime.UtcNow);
                    role.ConcurrencyStamp = Guid.NewGuid().ToString();
                    role.NormalizedName = role.Name.ToUpper().Trim();
                    result = await _roleManager.CreateAsync(role);
                    appRole = await _roleManager.FindByNameAsync(request.UserGroupName);

                    request.UserGroupId = appRole.Id;
                }
                else
                {
                    appRole.Name = request.UserGroupName;
                    result = await _roleManager.UpdateAsync(appRole);
                }

                if (!result.Succeeded)
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

                using (var scope = new TransactionScope(
                    TransactionScopeOption.Required,
                    new TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted },
                    TransactionScopeAsyncFlowOption.Enabled))
                {
                    var existingClaims = await _authContext.RoleClaims
                        .Where(x => x.RoleId == request.UserGroupId)
                        .ToListAsync();

                    foreach (var claim in request.Claims)
                    {
                        var existing = existingClaims
                            .FirstOrDefault(x => x.ClaimType == claim.ClaimType);

                        if (existing == null)
                        {
                            await _authContext.RoleClaims.AddAsync(new IdentityRoleClaim<string>
                            {
                                RoleId = request.UserGroupId,
                                ClaimType = claim.ClaimType,
                                ClaimValue = claim.ClaimValue
                            });
                        }
                        else
                        {
                            if (existing.ClaimValue != claim.ClaimValue)
                            {
                                existing.ClaimValue = claim.ClaimValue;
                                _authContext.RoleClaims.Update(existing);
                            }
                        }

                        if (claim.ClaimValue == "0" || claim.ClaimValue == "2")
                        {
                            var subUsers = await _authContext.UserClaims
                                .Where(x => x.ClaimType == claim.ClaimType && x.ClaimValue == "1")
                                .ToListAsync();

                            if (subUsers.Any())
                            {
                                subUsers.ForEach(x => x.ClaimValue = claim.ClaimValue);
                                _authContext.UserClaims.UpdateRange(subUsers);
                            }
                        }
                    }

                    _authContext.SaveChanges();
                    scope.Complete();
                }

                //force logout users in the same usergroup
                var users = await _userManager.GetUsersInRoleAsync(appRole.Name);
                var userIds = users.Select(x => x.Id).ToList();
                await ForceLogOutUsers(userIds);

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

                if (!result.Succeeded)
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

                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = true
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

        public async Task<BaseResponse<UserResponse>> GetCurrentUser(string userId)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(GetUserId(userId));

                var claimsModel = new List<ClaimModel>();
                if (user != null)
                {
                    var userClaim = await _userManager.GetClaimsAsync(user);
                    claimsModel = userClaim == null ? new List<ClaimModel>() : userClaim.Select(s => new ClaimModel { ClaimType = s.Type, ClaimValue = s.Value }).ToList();
                }

                var roleName = (await _userManager.GetRolesAsync(user)).FirstOrDefault();
                var role = await _roleManager.FindByNameAsync(roleName);

                return new BaseResponse<UserResponse>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = user == null ? new UserResponse() : new UserResponse
                    {
                        UserId = user.Id,
                        UserIdRef = user.IdRef,
                        NickName = user.NickName,
                        UserName = user.UserName,
                        Email = user.Email,
                        CreatedDate = user.CreatedDate,
                        AppId = user.AppId,
                        AppName = user.AppName,
                        MainUserId = user.MainUserId,
                        Status = user.LockoutEnd != null ? "Locked" : "Normal",
                        RoleId = role.Id,
                        RoleName = role.Name,
                        UserGroupIdRef = role.UserGroupIdRef,
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

        public async Task<BaseResponse<string>> CreateClientToken(ClientRegisterRequest request, string appId)
        {
            try
            {
                if (appId != $"{(int)Application.ClientChecklist}")
                    return new BaseResponse<string>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = $"{StatusCode.Unauthorized}"
                    };

                using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }))
                {
                    var sessionExpirationDate = DateTime.MaxValue;
                    var operatorToken = Guid.NewGuid();

                    var client = _authContext.UserTokens.FirstOrDefault(u => u.UserId == request.ClientId);

                    if (client == null)
                    {
                        var newToken = new AppToken
                        {
                            UserId = request.ClientId,
                            LoginProvider = appId,
                            Name = request.ClientName,
                            Value = string.Empty,
                            OperatorToken = operatorToken.ToString(),
                            SessionExpirationDate = sessionExpirationDate
                        };

                        _authContext.UserTokens.Add(newToken);
                    }
                    else
                    {
                        client.OperatorToken = operatorToken.ToString();
                    }

                    _authContext.SaveChanges();
                    scope.Complete();

                    return new BaseResponse<string>
                    {
                        StatusCode = StatusCode.Success,
                        Message = $"{StatusCode.Success}",
                        Result = operatorToken.ToString()
                    };
                }
            }
            catch (Exception ex)
            {
                return new BaseResponse<string>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }

        public async Task<BaseResponse<List<ClientTokenModel>>> GetClientTokens(string appId)
        {
            try
            {
                if (appId != $"{(int)Application.ClientChecklist}")
                    return new BaseResponse<List<ClientTokenModel>>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = $"{StatusCode.Unauthorized}"
                    };

                using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }))
                {
                    var clientTokens = _authContext.UserTokens.Where(u => u.LoginProvider == appId && string.IsNullOrEmpty(u.Value));

                    if (clientTokens.Any())
                    {
                        return new BaseResponse<List<ClientTokenModel>>
                        {
                            StatusCode = StatusCode.Success,
                            Message = $"{StatusCode.Success}",
                            Result = clientTokens.Select(s => new ClientTokenModel { UserId = s.UserId, OperatorToken = s.OperatorToken }).ToList()
                        };
                    }

                    return new BaseResponse<List<ClientTokenModel>>
                    {
                        StatusCode = StatusCode.Success,
                        Message = $"{StatusCode.Success}",
                        Result = new List<ClientTokenModel>()
                    };
                }
            }
            catch (Exception ex)
            {
                return new BaseResponse<List<ClientTokenModel>>
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

        private string GetUserId(string id)
        {
            if (long.TryParse(id, out long idRef))
            {
                var appUser = _authContext.Users.FirstOrDefault(x => x.IdRef == idRef);

                id = appUser == null || idRef == 0 ? id : appUser.Id;
            }
            return id;
        }
        private string GetRoleId(string id)
        {
            if (long.TryParse(id, out long userGroupIdRef))
            {
                var appRole = _authContext.Roles.FirstOrDefault(x => x.UserGroupIdRef == userGroupIdRef);

                id = appRole == null || userGroupIdRef == 0 ? id : appRole.Id;
            }

            return id;
        }

        private T ValidateReques<T>(T request)
        {
            if (typeof(T) == typeof(string))
            {
                var newT1 = "some text";
            }

            return (T)Convert.ChangeType("st", typeof(string));
        }
        private List<AppUser> GetUserList(string selection, string search = "", UserSorting sortBy = UserSorting.SortByCreateDateDesc, bool isShowSuperAdmin = false)
        {
            var users = new List<AppUser>();
            search = search.ToLower();

            //if (!string.IsNullOrWhiteSpace(selection.Trim()))
            //{
            //    users = _userManager.Users.AsNoTracking().Where(x => (x.MainUserId.ToLower() == selection.ToLower()) &&
            //            (string.IsNullOrWhiteSpace(search) ||
            //            x.UserName.ToLower().Contains(search) ||
            //            (x.NickName != null && x.NickName.ToLower().Contains(search)) ||
            //            x.Email.ToLower().Contains(search))).ToList();
            //}
            //else
            //{
            //    users = _userManager.Users.AsNoTracking().Where(x => string.IsNullOrWhiteSpace(x.MainUserId) &&
            //            (string.IsNullOrWhiteSpace(search) ||
            //            x.UserName.ToLower().Contains(search) ||
            //            (x.NickName != null && x.NickName.ToLower().Contains(search)) ||
            //            x.Email.ToLower().Contains(search))).ToList();
            //}
            if (!string.IsNullOrWhiteSpace(selection.Trim()))
            {
                users = _userManager.Users.AsNoTracking().Where(x => (x.MainUserId.ToLower() == selection.ToLower()) &&
                        (string.IsNullOrWhiteSpace(search) ||
                        x.UserName.ToLower().Contains(search))).ToList();
            }
            else
            {
                users = _userManager.Users.AsNoTracking().Where(x => string.IsNullOrWhiteSpace(x.MainUserId) &&
                        (string.IsNullOrWhiteSpace(search) ||
                        x.UserName.ToLower().Contains(search))).ToList();
            }

            if (!isShowSuperAdmin)
            {
                var superAdmin = _roleManager.Roles.AsNoTracking().Where(x => x.Name.Trim().ToUpper() == "SUPERADMIN").FirstOrDefault()?.Id ?? "";
                users = users.
                    Join(_authContext.UserRoles, user => user.Id, userRole => userRole.UserId, (user, userRole) => new { user, userRole.RoleId })
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

        private async Task<BaseResponse<PermissionResponse>> GetPermissionList(bool isSubUserOnly)
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

        private long ConvertToEpochTimestamp(DateTime date)
        {
            DateTime origin = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan diff = date.ToUniversalTime() - origin;

            var retval = long.Parse(Math.Floor(diff.TotalMilliseconds).ToString());

            return retval;
        }

        private async Task ForceLogOutUsers(string userId)
        {
            await ForceLogOutUsers(new List<string>() { userId });
        }
        private async Task ForceLogOutUsers(List<string> userIds)
        {
            var userTokens = _authContext.UserTokens.AsNoTracking().Where(x => userIds.Contains(x.UserId));

            if (userTokens.Any())
            {
                _authContext.UserTokens.RemoveRange(userTokens);

                _authContext.SaveChanges();
            }
        }
        #endregion
    }
}