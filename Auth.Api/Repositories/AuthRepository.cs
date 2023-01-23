using Auth.Api.Services;
using Auth.Shared.Data.Auth;
using Auth.Shared.Data.Auth.Entities;
using Auth.Shared.Enums;
using Auth.Shared.Models;
using Auth.Shared.Models.Response;
using Auth.Shared.Utilities;
using Azure.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Validations;
using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Reflection.Metadata;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Transactions;

namespace Auth.Api.Repositories
{
    public class AuthRepository : IAuthRepository
    {
        private IConfiguration _configuration { get; set; }
        private IUserIdentityService _userIdentityService { get; set; }
        private AuthContext _authContext { get; set; }
        private UserManager<AppUser> _userManager;
        private readonly byte[] TokenKey;
        private readonly string Issuer;

        public AuthRepository(AuthContext authContext,
            UserManager<AppUser> userManager,
            IConfiguration config,
            IUserIdentityService userIdentityService)
        {
            _authContext = authContext;
            _userManager = userManager;
            _configuration = config;
            _userIdentityService = userIdentityService;

            TokenKey = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
            Issuer = _configuration["JWT:Issuer"];
        }
        private async Task<SecurityTokenDescriptor> GenerateToken(string userId, IdentityRole role, string provider, string name, string mainUserId)
        {

            var token = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(),
                TokenType = "bearer",
                Expires = DateTime.UtcNow.AddMinutes(10),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(TokenKey), SecurityAlgorithms.HmacSha256Signature),
                Issuer = Issuer
            };
            token.Subject.AddClaim(new Claim("UserId", userId));

            token.Subject.AddClaim(new Claim("Provider", provider));
            token.Subject.AddClaim(new Claim("TokenName", name));
            token.Subject.AddClaim(new Claim("MainUserId", mainUserId));

            var isSubUser = false;

            if (mainUserId != null)
                if (!string.IsNullOrWhiteSpace(mainUserId))
                    isSubUser = true;

            var userClaims = new List<ClaimModel>();


            if (role.Name.ToLower() == "super admin")
            {
                var permissions = (await GetPermissionList(false)).Result.Permissions ?? new List<PermissionModel>();

                userClaims = permissions.Select(p => new ClaimModel { ClaimType = p.ClaimType, 
                    ClaimValue = p.ClaimType == Shared.Enums.ClaimTypes.SBC_Client_Access.ToString().Replace("_", ".") ? "" : "1" }).ToList();
            }
            else if (isSubUser)
                userClaims = _authContext.AspNetUserClaims.Where(x => x.UserId == userId)
                    .Select(x => new ClaimModel { ClaimType = x.ClaimType, ClaimValue = x.ClaimValue }).ToList();
            else
                userClaims = _authContext.AspNetRoleClaims.Join(_authContext.AspNetUserRoles, claims => claims.RoleId, roleClaims => roleClaims.RoleId,
                    (claims, roleClaims) => new  { Claims = claims, RoleClaims = roleClaims })
                    .Where(p => p.RoleClaims.UserId == userId && p.Claims.ClaimValue != "0")
                    .Select(p => new ClaimModel { ClaimType = p.Claims.ClaimType, ClaimValue = p.Claims.ClaimValue }).ToList();

            foreach (var item in userClaims)
            {
                if (item.ClaimType == Shared.Enums.ClaimTypes.SBC_Client_Access.ToString().Replace("_", "."))
                {
                    token.Subject.AddClaim(new Claim("ClientCodes", item.ClaimValue.ToString()));
                }
                else
                {
                    token.Subject.AddClaim(new Claim(item.ClaimType.ToString(), item.ClaimValue.ToString()));
                }
            }

            token.Subject.AddClaim(new Claim("RoleId", role.Id.ToString()));
            token.Subject.AddClaim(new Claim("RoleName", role.Name.ToString()));

            return token;
        }
        private async Task SaveToken(AppUser user, string token, LoginModel? loginModel = null)
        {

            if (loginModel == null)
                loginModel = _authContext.AspNetUserTokens.Where(x => x.UserId == user.Id).Select(x => new LoginModel()
                {
                    Name = x.Name,
                    Provider = x.LoginProvider
                }).FirstOrDefault();

            using (var scope = new TransactionScope(TransactionScopeOption.Required, new System.Transactions.TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }, TransactionScopeAsyncFlowOption.Enabled))
            {
                _authContext.AspNetUserTokens.RemoveRange(_authContext.AspNetUserTokens.Where(x => x.UserId == user.Id));
                _authContext.AspNetUserTokens.Add(new AspNetUserTokens()
                {
                    UserId = user.Id,
                    LoginProvider = loginModel.Provider,
                    Name = loginModel.Name,
                    Value = token
                });

                _authContext.ActivityLog.Add(new ActivityLog()
                {
                    UserId = user.Id,
                    Token = token,
                    BrowserInfo = loginModel.BrowserInfo,
                    BrowserVersion = loginModel.BrowserVersion,
                    OperatingSystem = loginModel.OperatingSystem,
                    IpAddress = loginModel.IpAddress,
                    Country = loginModel.Country,
                    Date = DateTime.UtcNow
                });

                _authContext.SaveChanges();
                scope.Complete();
            }
        }


        public async Task<BaseResponse<TokenModel>> Login(LoginModel content)
        {
            try
            {
                // if main user get from role claims
                // if sub user get from user claims
                var user = await _userManager.FindByNameAsync(content.Name);

                if (user == null)
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = "User does not exist.",
                        Result = null
                    };
                }

                if(user.LockoutEnd != null)
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = "User is locked.",
                        Result = null
                    };
                }

                if (_userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, content.Password) == PasswordVerificationResult.Success)
                {
                    var accessToken = "";

                    var role = (await _userIdentityService.GetCurrentUserRole(user)).Result;

                    var token = GenerateToken(user.Id, role, content.Provider, content.Name, user.MainUserId);
                    var tokenHandler = new JwtSecurityTokenHandler();
                    accessToken = tokenHandler.WriteToken(tokenHandler.CreateToken(token.Result));

                    SaveToken(user, accessToken, content);

                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = new TokenModel()
                        {
                            AccessToken = accessToken
                        }
                    };
                }
                return new BaseResponse<TokenModel>
                {
                    StatusCode = StatusCode.Unauthorized,
                    Message = "Incorrect password.",
                    Result = null
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<TokenModel>
                {
                    StatusCode = StatusCode.Error,
                    Message = ex.Message,
                    Result = null
                };
            }
        }
        public async Task<BaseResponse<bool>> Logout(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Unauthorized,
                    Message = "Empty Token.",
                    Result = false
                };
            }

            var tokenEntity = _authContext.AspNetUserTokens.Where(x => x.Value == token).FirstOrDefault();
            if (tokenEntity == null)
            {
                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Unauthorized,
                    Message = "Invalid Token.",
                    Result = false
                };
            }
            var parsedToken = JwtParser.ParseClaimsFromJwt(token).ToList();
            var provider = parsedToken.Where(x => x.Type == "Provider").Select(x => x.Value).FirstOrDefault();
            var name = parsedToken.Where(x => x.Type == "TokenName").Select(x => x.Value).FirstOrDefault();
            var userEntity = _authContext.AspNetUsers.Where(x => x.Id == tokenEntity.UserId).FirstOrDefault();

            if (userEntity == null)
            {
                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Unauthorized,
                    Message = "Invalid Token.",
                    Result = false
                };
            }

            var user = await _userManager.FindByNameAsync(userEntity.UserName);
            _authContext.AspNetUserTokens.Remove(_authContext.AspNetUserTokens.Where(x => x.Value == token && x.UserId == user.Id).FirstOrDefault());
            _authContext.SaveChangesAsync();

            return new BaseResponse<bool>
            {
                StatusCode = StatusCode.Success,
                Message = StatusCode.Success.ToString(),
                Result = true
            };
        }
        public async Task<BaseResponse<TokenModel>> Authenticate(string token)
        {
            try
            {
                SecurityToken jwtToken = null;

                if (string.IsNullOrWhiteSpace(token))
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = "Empty Token.",
                        Result = null
                    };
                }

                var handler = new JwtSecurityTokenHandler();
                jwtToken = handler.ReadToken(token);

                if (jwtToken == null)
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = "Invalid Token.",
                        Result = null
                    };
                }

                // Invalid Isuer
                if (jwtToken.Issuer != _configuration["JWT:Issuer"])
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = "Invalid Issuer.",
                        Result = null
                    };
                }

                //var tokenEntity = _authContext.AspNetUserTokens.Where(x => x.Value == token).FirstOrDefault();
                // Expired
                if (jwtToken.ValidTo.AddMinutes(5) < DateTime.Now)
                {
                    var parsedToken = JwtParser.ParseClaimsFromJwt(token).ToList();
                    var provider = parsedToken.Where(x => x.Type == "Provider").Select(x => x.Value).FirstOrDefault();
                    var name = parsedToken.Where(x => x.Type == "TokenName").Select(x => x.Value).FirstOrDefault();
                    var userId = parsedToken.Where(x => x.Type == "UserId").Select(x => x.Value).FirstOrDefault();

                    var user = _userManager.FindByNameAsync(name).Result;
                    if (user == null)
                    {
                        return new BaseResponse<TokenModel>
                        {
                            StatusCode = StatusCode.Unauthorized,
                            Message = "Invalid Token.",
                            Result = null
                        };
                    }

                    var role = (await _userIdentityService.GetCurrentUserRole(user)).Result;

                    var tokenHandler = new JwtSecurityTokenHandler();
                    token = tokenHandler.WriteToken(tokenHandler.CreateToken(await GenerateToken(userId, role, provider, name, user.MainUserId)));

                    SaveToken(user, token);
                }

                return new BaseResponse<TokenModel>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = new TokenModel()
                    {
                        AccessToken = token
                    }
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<TokenModel>
                {
                    StatusCode = StatusCode.Error,
                    Message = ex.Message,
                    Result = null
                };
            }
        }
        public async Task<BaseResponse<PermissionResponse>> GetPermissionList(bool isSubUserOnly)
        {
            var result = await _authContext.Permission.Where(p => isSubUserOnly == false || p.IsSubUser == isSubUserOnly).ToListAsync();

            var permList = result.Select(a => new PermissionModel()
            {
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

        public async Task<BaseResponse<ActivityLogResponse>> GetActivityLogList(string userId)
        {
            try
            {
                return new BaseResponse<ActivityLogResponse>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = null
                };
            }
            catch (Exception ex)
            {
                return new BaseResponse<ActivityLogResponse>
                {
                    StatusCode = StatusCode.Error,
                    Message = ex.Message,
                    Result = null
                };
            }
        }
    }
}
