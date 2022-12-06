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
using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
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
        private async Task<SecurityTokenDescriptor> GenerateToken(string userId, string provider, string name)
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

            var userClaims = _authContext.AspNetRoleClaims.Join(_authContext.AspNetUserRoles, claims => claims.RoleId, roleClaims => roleClaims.RoleId,
                (claims, roleClaims) => new { Claims = claims, RoleClaims = roleClaims })
                .Where(p => p.RoleClaims.UserId == userId && p.Claims.ClaimValue != "0")
                .Select(p => new { p.Claims.ClaimType, p.Claims.ClaimValue }).ToList();

            foreach (var item in userClaims)
            {
                if (item.ClaimType == Shared.Enums.ClaimTypes.SportsbookClient_Client_Access.ToString().Replace("_", "."))
                {
                    token.Subject.AddClaim(new Claim("ClientCodes", item.ClaimValue.ToString()));
                }
                else
                {
                    token.Subject.AddClaim(new Claim(item.ClaimType.ToString(), item.ClaimValue.ToString()));
                }
            }

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

                _authContext.SaveChanges();
                scope.Complete();
            }
        }


        public async Task<BaseResponse<TokenModel>> Login(LoginModel content)
        {
            try
            {
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

                if (_userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, content.Password) == PasswordVerificationResult.Success)
                {
                    var accessToken = "";
                    var token = GenerateToken(user.Id, content.Provider, content.Name);
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

                var tokenEntity = _authContext.AspNetUserTokens.Where(x => x.Value == token).FirstOrDefault();
                // Expired
                if (jwtToken.ValidTo < DateTime.UtcNow)
                {
                    var parsedToken = JwtParser.ParseClaimsFromJwt(token).ToList();
                    var provider = parsedToken.Where(x => x.Type == "Provider").Select(x => x.Value).FirstOrDefault();
                    var name = parsedToken.Where(x => x.Type == "TokenName").Select(x => x.Value).FirstOrDefault();
                    var userEntity = _authContext.AspNetUsers.Where(x => x.Id == tokenEntity.UserId).FirstOrDefault();

                    if (userEntity == null)
                    {
                        return new BaseResponse<TokenModel>
                        {
                            StatusCode = StatusCode.Unauthorized,
                            Message = "Invalid Token.",
                            Result = null
                        };
                    }

                    var user = await _userManager.FindByNameAsync(userEntity.UserName);

                    var tokenHandler = new JwtSecurityTokenHandler();
                    token = tokenHandler.WriteToken(tokenHandler.CreateToken(await GenerateToken(tokenEntity.UserId, tokenEntity.LoginProvider, tokenEntity.Name)));

                    SaveToken(user, token);
                }
                else
                {
                    if (tokenEntity == null)
                    {
                        return new BaseResponse<TokenModel>
                        {
                            StatusCode = StatusCode.Unauthorized,
                            Message = "Invalid Token.",
                            Result = null
                        };
                    }
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
                Category = a.Category,
                Name = a.Name,
                ClaimType = a.ClaimType,
                HasReadOnly = a.HasReadOnly,
                SortOrder = a.SortOrder,
                IsSubUser = a.IsSubUser
            }).OrderBy(x => x.Category).ThenBy(o => o.SortOrder).ToList();

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

    }
}
