using Auth.Shared.Data.Auth;
using Auth.Shared.Enums;
using Auth.Shared.Models;
using Auth.Shared.Models.Request;
using Auth.Shared.Models.Response;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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
        #endregion

        #region Ctor
        public UserIdentityService(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, UserIdentityContext userIdentityContext)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _userIdentityContext = userIdentityContext;
        }
        #endregion

        #region Methods
        public async Task<BaseResponse<UserListResponse>> GetAspNetUsersList(string search = "", bool showSuperAdmin = false)
        {
            try
            {
                var result = _userManager.Users.AsNoTracking();

                if (!string.IsNullOrEmpty(search))
                    result = result.Where(result => result.UserName.ToLower().Contains(search.ToLower()));

                if (!showSuperAdmin)
                    result = result.Where(result => result.UserName.ToLower() != "fci-admin");


                var response = new List<UserResponse>();
                if (result.Any())
                {
                    response = result.Select(s => new UserResponse
                    {
                        UserId = s.Id,
                        NickName = s.NickName,
                        UserName = s.UserName,
                        Email = s.Email,
                        CreatedDate = s.CreatedDate,
                        AppId = s.AppId,
                        AppName = s.AppName,
                        MainUserId = s.MainUserId,
                        Status = s.LockoutEnd != null ? (s.LockoutEnd < DateTime.UtcNow ? "Normal" : "Locked") : "Normal"
                    }).ToList();
                }

                return new BaseResponse<UserListResponse>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = new UserListResponse()
                    {
                        Users = response
                    }
                };
            }
            catch (Exception ex)
            {
                return null;
            }

        }

        public async Task<BaseResponse<UserListResponse>> GetAspNetSubAccountList(SubAccountListRequest request)
        {
            try
            {
                var result = _userManager.Users.AsNoTracking().Where(u => u.MainUserId == request.MainUserId);

                var users = new List<AppUser>();
                var metaData = new MetaData();
                if (request.Page > 0 && request.PageSize > 0)
                {
                    var rowCount = result.Count();
                    var skip = (request.Page - 1) * request.PageSize;
                    var totalPage = ((rowCount - 1) / request.PageSize) + 1;

                    users = result.Skip(skip).Take(request.PageSize).ToList();

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
                    response = users.Select(s => new UserResponse
                    {
                        UserId = s.Id,
                        NickName = s.NickName,
                        UserName = s.UserName,
                        Email = s.Email,
                        CreatedDate = s.CreatedDate,
                        AppId = s.AppId,
                        AppName = s.AppName,
                        MainUserId = s.MainUserId,
                        Status = s.LockoutEnd != null ? (s.LockoutEnd < DateTime.UtcNow ? "Normal" : "Locked") : "Normal"
                    }).ToList();
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

        public async Task<List<AppRole>> GetAspNetRolesList(string search = "", bool showSuperAdmin = false)
        {
            try
            {
                var query = _roleManager.Roles.AsNoTracking();

                if (!string.IsNullOrEmpty(search))
                    query = query.Where(result => result.Name.Contains(search));

                if (!showSuperAdmin)
                    query = query.Where(c => c.Name.ToLower() != "super admin");

                var result = new List<AppRole>();
                var roles = query.ToList();

                foreach (var role in roles)
                {
                    var userCount = (await _userManager.GetUsersInRoleAsync(role.Name)).Count;

                    result.Add(new AppRole
                    {
                        Id = role.Id,
                        Name = role.Name,
                        NormalizedName = role.NormalizedName,
                        ConcurrencyStamp = role.ConcurrencyStamp,
                        UserCount = userCount
                    });
                }

                return result;
            }
            catch (Exception ex)
            {
                return null;
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
        public async Task<List<AppUser>> GetAspNetRoleUsers(string roleId)
        {
            try
            {
                var userRoles = _userIdentityContext.UserRoles.AsNoTracking().ToList();
                var users = _userManager.Users.AsNoTracking().ToList();

                var result = (from ur in userRoles
                              join u in users on ur.UserId equals u.Id
                              where ur.RoleId == roleId
                              select new AppUser
                              {
                                  Id = u.Id,
                                  UserName = u.UserName,

                              }).ToList();

                return result;
            }
            catch (Exception ex)
            {
                return null;
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
        public async Task<List<Claim>> GetAspNetRoleClaims(string roleId)
        {
            try
            {
                var role = await _roleManager.FindByIdAsync(roleId);
                var result = await _roleManager.GetClaimsAsync(role);

                return result.ToList();
            }
            catch (Exception ex)
            {
                return null;
            }

        }
        public async Task<List<Claim>> GetAspNetRoleClaimsByName(string roleName)
        {
            try
            {
                var role = await _roleManager.FindByNameAsync(roleName);
                var result = await _roleManager.GetClaimsAsync(role);

                return result.ToList();
            }
            catch (Exception ex)
            {
                return null;
            }

        }
        public async Task<List<IdentityRoleClaim<string>>> GetAspNetRoleClaims2(string roleId)
        {
            try
            {
                var role = _roleManager.Roles.FirstOrDefault(c => c.Id == roleId);
                var result = _userIdentityContext.RoleClaims.Where(c => c.RoleId == roleId).ToList();

                return result.ToList();
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
                    AppName = request.AppName
                };

                user.LockoutEnd = null;
                if (request.Status.ToUpper() == "Locked".ToUpper())
                    user.LockoutEnd = DateTime.UtcNow;

                //var isvalid = await _userManager.UserValidators(request);
                IdentityResult result = await _userManager.CreateAsync(user, request.Password);
                if (result.Succeeded)
                {
                    var addRole = await _userManager.AddToRoleAsync(user, request.RoleName);

                    if(user.MainUserId != null)
                        if(!string.IsNullOrWhiteSpace(user.MainUserId))
                        {
                            await _userManager.AddClaimsAsync(user, request.UserClaims);
                        }

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString()
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

                //return new BaseResponse<bool>
                //{
                //    StatusCode = StatusCode.Success,
                //    Message = StatusCode.Success.ToString()
                //};
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
                            await _userManager.AddClaimsAsync(user, request.UserClaims);
                        }

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString()
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
                        Message = StatusCode.Success.ToString()
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
        public async Task<BaseResponse<bool>> AddAspNetRoles(string roleName, List<AppRoleClaim> tmpRoleClaims)
        {
            try
            {
                IdentityResult result = await _roleManager.CreateAsync(new IdentityRole(roleName));
                var appRole = await _roleManager.FindByNameAsync(roleName);
                if (result.Succeeded)
                {
                    foreach (var claims in tmpRoleClaims)
                    {
                        Claim newClaims = new Claim(claims.ClaimType, claims.ClaimValue);
                        await _roleManager.AddClaimAsync(appRole, newClaims);
                    }

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString()
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
        public async Task<BaseResponse<bool>> UpdateAspNetRoles(AppRole request, List<AppRoleClaim> tmpRoleClaims)
        {
            try
            {

                var appRole = await _roleManager.FindByIdAsync(request.Id);
                appRole.Name = request.Name;

                IdentityResult result = await _roleManager.UpdateAsync(appRole);
                if (result.Succeeded)
                {
                    using (var scope = new TransactionScope(TransactionScopeOption.Required, new System.Transactions.TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }, TransactionScopeAsyncFlowOption.Enabled))
                    {
                        foreach (var claims in tmpRoleClaims)
                        {
                            var newClaims = _userIdentityContext.RoleClaims.FirstOrDefault(x => x.RoleId == request.Id && x.ClaimType == claims.ClaimType);
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

                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString()
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
        public async Task<BaseResponse<bool>> DeleteAspNetRoles(AppRole request)
        {
            try
            {
                var appRole = await _roleManager.FindByIdAsync(request.Id);
                var appUsers = await GetAspNetRoleUsers(request.Id);
                IdentityResult result = await _roleManager.DeleteAsync(appRole);
                foreach (var user in appUsers)
                {
                    var userRequest = new UserRegisterRequest
                    {
                        UserName = user.UserName,
                        Email = user.Email,
                        AppId = user.AppId,
                        AppName = user.AppName,
                        RoleName = "Default"
                    };

                    var addResult = await UpdateAspNetUsers(userRequest, true);
                }
                //var removeRoles = await _userManager.RemoveFromRolesAsync(user, oldRoles);
                //var addRole = await _userManager.AddToRoleAsync(user, roleName);
                if (result.Succeeded)
                {


                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString()
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
                var roleName = (await _userManager.GetRolesAsync(user)).FirstOrDefault();
                var role = await _roleManager.FindByNameAsync(roleName);

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
                        Status = user.LockoutEnd != null ? (user.LockoutEnd < DateTime.UtcNow ? "Normal" : "Locked") : "Normal"
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
        public void Dispose()
        {
            _roleManager.Dispose();
            _userManager.Dispose();
        }
        #endregion
    }
}