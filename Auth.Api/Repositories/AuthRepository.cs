using Auth.Shared.Data.Auth;
using Auth.Shared.Data.Auth.Entities;
using Auth.Shared.Enums;
using Auth.Shared.Models;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Transactions;

namespace Auth.Api.Repositories
{
    public class AuthRepository : IAuthRepository
    {
        private IConfiguration _configuration { get; set; }
        private AuthContext _authContext { get; set; }
        private UserManager<IdentityUser> _userManager;
        public AuthRepository(AuthContext authContext,
            UserManager<IdentityUser> userManager,
            IConfiguration config)
        {
            this._authContext = authContext;
            this._userManager = userManager;
            this._configuration = config;
        }
        private async Task<SecurityTokenDescriptor> GenerateToken(string userId, byte[] tokenKey, string issuer)
        {
            // Include AspNetUserClaims in Claims
            // Include UserId in claims

            var claims = _authContext.AspNetRoleClaims.Join(_authContext.AspNetUserRoles, claims => claims.RoleId, userRoles => userRoles.RoleId,
                (claims, userRoles) => new { Claims = claims, UserRoles = userRoles })
                .Where(p => p.UserRoles.UserId == userId && p.Claims.ClaimValue != "0")
                .Select(p => new { p.Claims.ClaimType, p.Claims.ClaimValue }).ToList();

            var token = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(),
                TokenType = "bearer",
                Expires = DateTime.UtcNow.AddMinutes(10),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature),
                Issuer = issuer
            };
            foreach (var item in claims)
            {
                token.Subject.AddClaim(new Claim(item.ClaimType.ToString(), item.ClaimValue.ToString()));
            }
            return token;
        }
        public async Task<BaseResponse<TokenModel>> Authenticate(UserModel content)
        {
            var timer = new Stopwatch();
            timer.Start();
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
                    var result = new Tokens();
                    using (var scope = new TransactionScope(TransactionScopeOption.Required, new System.Transactions.TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }, TransactionScopeAsyncFlowOption.Enabled))
                    {
                        var tokenKey = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
                        var issuer = _configuration["JWT:Issuer"];
                        var token = GenerateToken(user.Id, tokenKey, issuer);

                        var refresh = new SecurityTokenDescriptor
                        {
                            Subject = new ClaimsIdentity(),
                            Expires = DateTime.UtcNow.AddDays(0.5),
                            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature),
                            Issuer = issuer
                        };

                        var tokenHandler = new JwtSecurityTokenHandler();

                        result = new Tokens()
                        {
                            Id = Guid.NewGuid().ToString(),
                            UserId = user.Id,
                            AccessToken = tokenHandler.WriteToken(tokenHandler.CreateToken(token.Result)),
                            TokenType = token.Result.TokenType,
                            TokenExpiration = token.Result.Expires.Value,
                            RefreshToken = tokenHandler.WriteToken(tokenHandler.CreateToken(refresh)),
                            RefreshExpiration = refresh.Expires.Value,
                        };

                        await _authContext.AddAsync(result);
                        _authContext.Entry(result).State = EntityState.Added;

                        _authContext.SaveChanges();
                        scope.Complete();
                    }

                    timer.Stop();

                    TimeSpan timeTaken = timer.Elapsed;
                    string foo = "Time taken: " + timeTaken.ToString(@"m\:ss\.fff");
                    Console.WriteLine(foo);

                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = new TokenModel()
                        {
                            Token = result.AccessToken,
                            Refresh = result.RefreshToken
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
        public async Task<BaseResponse<TokenModel>> Authenticate(string content)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(content))
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = "Empty Token.",
                        Result = null
                    };
                }

                var handler = new JwtSecurityTokenHandler();
                var jsonToken = handler.ReadToken(content);

                if (jsonToken == null)
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = "Invalid Token.",
                        Result = null
                    };
                }

                // Expired
                if (jsonToken.ValidTo < DateTime.UtcNow)
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = "Expired Token.",
                        Result = null
                    };
                }

                // Invalid Isuer
                if (jsonToken.Issuer != _configuration["JWT:Issuer"])
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = "Invalid Issuer.",
                        Result = null
                    };
                }

                var result = new Tokens();
                using (var scope = new TransactionScope(TransactionScopeOption.Required, new System.Transactions.TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }, TransactionScopeAsyncFlowOption.Enabled))
                {
                    var tokenEntity = _authContext.Tokens.Where(x => x.RefreshExpiration > DateTime.UtcNow && x.RefreshToken == content).FirstOrDefault();
                    if (tokenEntity == null)
                    {
                        return new BaseResponse<TokenModel>
                        {
                            StatusCode = StatusCode.Unauthorized,
                            Message = "Invalid Token.",
                            Result = null
                        };
                    }

                    var tokenKey = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
                    var issuer = _configuration["JWT:Issuer"];
                    var token = GenerateToken(tokenEntity.UserId, tokenKey, issuer);

                    var tokenHandler = new JwtSecurityTokenHandler();
                    result = new Tokens()
                    {
                        Id = Guid.NewGuid().ToString(),
                        UserId = tokenEntity.UserId,
                        AccessToken = tokenHandler.WriteToken(tokenHandler.CreateToken(token.Result)),
                        TokenType = token.Result.TokenType,
                        TokenExpiration = token.Result.Expires.Value,
                        RefreshToken = content,
                        RefreshExpiration = jsonToken.ValidTo
                    };

                    await _authContext.AddAsync(result);
                    _authContext.Entry(result).State = EntityState.Added;

                    _authContext.SaveChanges();
                    scope.Complete();
                }

                return new BaseResponse<TokenModel>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = new TokenModel()
                    {
                        Token = result.AccessToken,
                        Refresh = result.RefreshToken
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
    }
}
