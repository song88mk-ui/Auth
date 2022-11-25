using Auth.Shared.Data.Auth;
using Auth.Shared.Enums;
using Auth.Shared.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Transactions;

namespace Auth.Api.Services
{
    public class UserIdentityService : IUserIdentityService, IDisposable
    {
        #region Fields
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserIdentityContext _userIdentityContext;
        #endregion

        #region Ctor
        public UserIdentityService(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, UserIdentityContext userIdentityContext)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _userIdentityContext = userIdentityContext;
        }
        #endregion

        #region Methods
        public async Task<List<IdentityUser>> GetAspNetUsersList(string search = "", bool showSuperAdmin = false)
        {
            try
            {
                var result = _userManager.Users.AsNoTracking();

                if (!string.IsNullOrEmpty(search))
                    result = result.Where(result => result.UserName.ToLower().Contains(search.ToLower()));

                if (!showSuperAdmin)
                    result = result.Where(result => result.UserName.ToLower() != "fci-admin");

                return result.ToList();
            }
            catch (Exception ex)
            {
                return null;
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

        public async Task<BaseResponse<bool>> AddAspNetUsers(AppUser request, string roleName)
        {
            try
            {
                //request.EmailConfirmed = true;
                request.EmailConfirmed = request.Status == "Normal" ? true : false;
                //var isvalid = await _userManager.UserValidators(request);
                IdentityResult result = await _userManager.CreateAsync(request, request.PasswordHash);
                if (result.Succeeded)
                {
                    var addRole = await _userManager.AddToRoleAsync(request, roleName);
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
        public async Task<BaseResponse<bool>> UpdateAspNetUsers(AppUser request, string roleName, bool isDefault = false)
        {
            try
            {
                var user = (await _userManager.FindByIdAsync(request.Id));
                if (!isDefault)
                {
                    user.Email = request.Email;
                    user.EmailConfirmed = request.Status == "Normal" ? true : false;
                }


                //if (request.PasswordHash != null)
                //{
                //    var passwordValidator = new PasswordValidator<IdentityUser>();
                //    var isValid = await passwordValidator.ValidateAsync(_userManager, null, request.PasswordHash);

                //    if (isValid.Succeeded)
                //    {
                //        user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, request.PasswordHash);
                //    }
                //    else
                //    {
                //        string errorMsg = "";
                //        foreach (IdentityError error in isValid.Errors)
                //            errorMsg += error.Description.ToString() + ",";

                //        return new BaseResponse<bool>
                //        {
                //            StatusCode = StatusCode.Error,
                //            Message = $"{errorMsg.TrimEnd(',')} "
                //        };
                //    }

                //}


                var oldRoles = await _userManager.GetRolesAsync(user);
                var removeRoles = await _userManager.RemoveFromRolesAsync(user, oldRoles);
                var addRole = await _userManager.AddToRoleAsync(user, roleName);

                var result = await _userManager.UpdateAsync(user);

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
        public async Task<BaseResponse<bool>> ChangePasswordAspNetUsers(AppUser request)
        {
            try
            {
                var user = _userManager.FindByIdAsync(request.Id).Result;

                if (request.PasswordHash != null)
                {
                    var passwordValidator = new PasswordValidator<IdentityUser>();
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
                    var addResult = await UpdateAspNetUsers(user, "Default", true);
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

        public async Task<BaseResponse<IdentityUser>> GetCurrentUser(ClaimsPrincipal principal)
        {
            try
            {
                var user = await _userManager.GetUserAsync(principal);

                return new BaseResponse<IdentityUser>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = user
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<IdentityUser>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }
        public async Task<BaseResponse<IdentityRole>> GetCurrentUserRole(IdentityUser user)
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
        public async Task<BaseResponse<IdentityUser>> GetCurrentUser(string userId)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);

                return new BaseResponse<IdentityUser>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = user
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<IdentityUser>
                {
                    StatusCode = StatusCode.Error,
                    Message = $"{StatusCode.Error.ToString().Replace('_', ' ')} ({ex.Message})"
                };
            }
        }
        public async Task<BaseResponse<bool>> ChangePassword(IdentityUser user, string currentPassword, string newPassword)
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