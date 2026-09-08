using Auth.Api.Services;
using Auth.Api.Telemetry;
using Auth.Shared.Data.Auth;
using Auth.Shared.Data.Auth.Entities;
using Auth.Shared.Enums;
using Auth.Shared.Models;
using Auth.Shared.Models.Response;
using Auth.Shared.Utilities;
using Azure.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Transactions;

namespace Auth.Api.Repositories
{
    public class AuthRepository : IAuthRepository
    {
        #region Properties

        private IConfiguration _configuration { get; set; }
        private IAuthService _userIdentityService { get; set; }
        private readonly IMemCache _memCache;
        private AuthContext _authContext { get; set; }
        private int _sessionExpirationInSeconds = 300;
        private int _sessionExpirationInMonths = 3;
        private readonly ActivitySource _activitySource;
        private readonly Counter<long> _loginSuccessCounter;
        private readonly Counter<long> _loginFailureCounter;

        #endregion

        #region Fields

        private UserManager<AppUser> _userManager;
        private readonly byte[] TokenKey;
        private readonly string Issuer;

        #endregion

        #region CTOR

        public AuthRepository(AuthContext authContext,
            UserManager<AppUser> userManager,
            IConfiguration config,
            IAuthService userIdentityService,
            IMemCache memCache,
            Instrumentation instrumentation)
        {
            _authContext = authContext;
            _userManager = userManager;
            _configuration = config;
            _userIdentityService = userIdentityService;

            TokenKey = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
            Issuer = _configuration["JWT:Issuer"] ?? string.Empty;
            _memCache = memCache;
            _activitySource = instrumentation.ActivitySource;
            _loginSuccessCounter = instrumentation.LoginSuccessCounter;
            _loginFailureCounter = instrumentation.LoginFailureCounter;
        }

        #endregion

        #region Methods

        private async Task<SecurityTokenDescriptor> GenerateToken(string userId, IdentityRole role, string provider, string name, string mainUserId, string nickname, int version = 0, long userIdRef = 0l, long mainUserIdRef = 0l)
        {
            var expiration = provider.Equals($"{(int)Application.ClientChecklist}") ? DateTime.MaxValue : DateTime.UtcNow.AddMonths(3);

            var token = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(),
                TokenType = "Bearer",
                Expires = expiration,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(TokenKey), SecurityAlgorithms.HmacSha256Signature),
                Issuer = Issuer,
                Audience = Issuer
            };
            token.Subject.AddClaim(new Claim("UserId", userId));
            token.Subject.AddClaim(new Claim("UserIdRef", userIdRef.ToString()));
            token.Subject.AddClaim(new Claim("Provider", provider));
            token.Subject.AddClaim(new Claim("TokenName", name));
            token.Subject.AddClaim(new Claim("MainUserId", mainUserId));
            token.Subject.AddClaim(new Claim("MainUserIdRef", mainUserIdRef.ToString()));
            token.Subject.AddClaim(new Claim("Nickname", nickname ?? string.Empty));

            var isSubUser = false;

            if (mainUserId != null)
                if (!string.IsNullOrWhiteSpace(mainUserId))
                    isSubUser = true;

            Claim? clients = null;
            var claims = new List<Claim>();

            var hasAdmin = true;

            if (role != null && role.Name.ToLower() == "super admin")
            {
                claims = (from permissions in _authContext.Permission
                          where permissions.CategoryId != 99
                          select new Claim(permissions.ClaimType, "1", $"{permissions.HasReadOnly}.{permissions.SortOrder}")).ToList();

                clients = claims.Where(x => x.Type == Shared.Enums.ClaimTypes.SBC_Clients_Access.ToString().Replace('_', '.')).Select(x => new Claim(x.Type, "ALL")).FirstOrDefault();
            }
            else
            {
                var permissionVersions = new List<int>() { 0, 1, 2 };
                if (version == 2)
                    permissionVersions = new List<int>() { 0, 2 };

                if (isSubUser)
                {
                    var mainUserClaims = (from roleClaims in _authContext.RoleClaims
                                          join roles in _authContext.UserRoles on roleClaims.RoleId equals roles.RoleId
                                          join permissions in _authContext.Permission on roleClaims.ClaimType equals permissions.PermissionId.ToString()
                                          where permissions.CategoryId != 99 && roleClaims.ClaimValue != "0" && roles.UserId == mainUserId && permissionVersions.Contains(permissions.Version)
                                          select new ClaimModel() { ClaimType = permissions.ClaimType.ToString(), ClaimValue = roleClaims.ClaimValue }).ToList();

                    var tempClaims = (from userClaims in _authContext.UserClaims
                                      join permissions in _authContext.Permission on userClaims.ClaimType equals permissions.PermissionId.ToString()
                                      where userClaims.UserId == userId && userClaims.ClaimValue != "0" && permissions.IsSubUser == true && permissionVersions.Contains(permissions.Version)
                                      select new Claim(permissions.ClaimType, userClaims.ClaimValue, $"{permissions.HasReadOnly}.{permissions.SortOrder}")).ToList();

                    claims = tempClaims.Where(x => mainUserClaims.Any(c => c.ClaimType == x.Type && c.ClaimValue == x.Value)).Select(x => new Claim(x.Type, x.Value, x.ValueType)).ToList();

                    clients = (from roleClaims in _authContext.RoleClaims
                               join roles in _authContext.UserRoles on roleClaims.RoleId equals roles.RoleId
                               join permissions in _authContext.Permission on roleClaims.ClaimType equals permissions.PermissionId.ToString()
                               where roles.UserId == mainUserId && permissions.ClaimType == Shared.Enums.ClaimTypes.SBC_Clients_Access.ToString().Replace('_', '.')
                               select new Claim(permissions.ClaimType, roleClaims.ClaimValue)).FirstOrDefault();
                }
                else
                {
                    claims = (from roleClaims in _authContext.RoleClaims
                              join roles in _authContext.UserRoles on roleClaims.RoleId equals roles.RoleId
                              join permissions in _authContext.Permission on roleClaims.ClaimType equals permissions.PermissionId.ToString()
                              where permissions.CategoryId != 99 && roleClaims.ClaimValue != "0" && roles.UserId == userId && permissionVersions.Contains(permissions.Version)
                              select new Claim(permissions.ClaimType, roleClaims.ClaimValue, $"{permissions.HasReadOnly}.{permissions.SortOrder}")).ToList();

                    clients = claims.FirstOrDefault(x => x.Type == Shared.Enums.ClaimTypes.SBC_Clients_Access.ToString().Replace('_', '.'));
                }

                hasAdmin = claims.Any(x => x.Type.StartsWith($"{PermissionAccess.Admin.ToString()}."));
            }

            var subUserAccess = claims.FirstOrDefault(x => x.Type == Shared.Enums.ClaimTypes.SBC_SubUsers.ToString().Replace("_", "."));

            if (subUserAccess != null && hasAdmin)
            {
                claims.Remove(subUserAccess);
            }

            if (clients != null)
            {
                claims.Remove(clients);
                claims.Add(new Claim("ClientCodes", clients.Value));
            }

            token.Subject.AddClaims(claims);

            token.Subject.AddClaim(new Claim("Permission", role != null ? role.Id.ToString() : string.Empty));
            token.Subject.AddClaim(new Claim("RoleId", role != null ? role.Id.ToString() : string.Empty));
            token.Subject.AddClaim(new Claim("RoleName", role != null ? role.Name.ToString() : string.Empty));

            return token;
        }
        private void SaveToken(AppUser user, string token, string operatorToken, LoginModel? loginModel = null)
        {
            using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }))
            {
                var oldToken = _authContext.UserTokens.Where(x => x.UserId == user.Id).FirstOrDefault();
                var sessionExpirationDate = loginModel?.Provider == $"{(int)Application.ClientChecklist}" ? DateTime.MaxValue : DateTime.UtcNow.AddMonths(_sessionExpirationInMonths);

                if (oldToken != null)
                {
                    oldToken.Value = token;
                    oldToken.OperatorToken = operatorToken;
                    oldToken.SessionExpirationDate = sessionExpirationDate;

                    _authContext.UserTokens.Update(oldToken);

                    _memCache.AddOrUpdateCache($"ot:{operatorToken}", oldToken, DateTimeOffset.UtcNow.AddDays(1));
                }
                else
                {
                    var newToken = new AppToken
                    {
                        UserId = user.Id,
                        LoginProvider = loginModel.Provider,
                        Name = loginModel.Username,
                        Value = token,
                        OperatorToken = operatorToken,
                        SessionExpirationDate = sessionExpirationDate
                    };

                    _authContext.UserTokens.Add(newToken);

                    _memCache.AddOrUpdateCache($"ot:{operatorToken}", newToken, DateTimeOffset.UtcNow.AddDays(1));
                }


                if (loginModel != null)
                {
                    _authContext.ActivityLog.Add(new ActivityLog()
                    {
                        UserId = user.Id,
                        Token = token,
                        UserAgent = loginModel.UserAgent,
                        IpAddress = loginModel.IpAddress,
                        Country = loginModel.Country,
                        Date = DateTime.UtcNow
                    });
                }

                _authContext.SaveChanges();
                scope.Complete();
            }
        }

        public async Task<BaseResponse<TokenModel>> Login(LoginModel content, int version)
        {
            using (var activity = _activitySource.StartActivity("login"))
                try
                {
                    if (content != null)
                    {
                        if (!string.IsNullOrEmpty(content.IpAddress))
                        {
                            if (content.IpAddress == "::1")
                            {
                                content.IpAddress = Dns.GetHostEntry(Dns.GetHostName()).AddressList[1].ToString();
                            }
                            if (string.IsNullOrEmpty(content.Country))
                                content.Country = GetUserCountryByIp(content.IpAddress);
                        }

                        content.Country = content.Country ?? "";
                    }

                    activity?.SetTag("user.name", content.Username);
                    activity?.SetTag("ip.address", content.IpAddress);
                    activity?.SetTag("country.code", content.Country);

                    // if main user get from role claims
                    // if sub user get from user claims
                    var user = await _userManager.FindByNameAsync(content.Username);
                    var mainUserIdRef = 0l;

                    if (user == null)
                    {
                        _loginFailureCounter.Add(1);
                        return new BaseResponse<TokenModel>
                        {
                            StatusCode = StatusCode.Username_Not_Found,
                            Message = "Sorry, we couldn’t find an account with that username. Please try again.",
                            Result = null
                        };
                    }

                    if (user.AppId.ToString() != content.Provider)
                    {
                        _loginFailureCounter.Add(1);

                        return new BaseResponse<TokenModel>
                        {
                            StatusCode = StatusCode.Unauthorized,
                            Message = "User does not exist.",
                            Result = null
                        };
                    }

                    if (user.LockoutEnd != null)
                    {
                        _loginFailureCounter.Add(1);

                        return new BaseResponse<TokenModel>
                        {
                            StatusCode = StatusCode.User_Is_Locked,
                            Message = "User is locked.",
                            Result = null
                        };
                    }

                    var role = await _userIdentityService.GetCurrentUserRole(user);

                    if (!string.IsNullOrEmpty(user.MainUserId) && user.MainUserId != "0")
                    {
                        var mainUser = await _userManager.FindByIdAsync(user.MainUserId);
                        mainUserIdRef = mainUser.IdRef;
                        role = await _userIdentityService.GetCurrentUserRole(mainUser);
                    }

                    if (_userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, content.Password) != PasswordVerificationResult.Success)
                    {

                        //var vtoken = await _userManager.GeneratePasswordResetTokenAsync(user);
                        //var result = await _userManager.ResetPasswordAsync(user, vtoken, content.Password);

                        _loginFailureCounter.Add(1);

                        return new BaseResponse<TokenModel>
                        {
                            StatusCode = StatusCode.Invalid_Password,
                            Message = "Invalid Password. Please try again.",
                            Result = null
                        };
                    }

                    var accessToken = string.Empty;

                    var token = await GenerateToken(user.Id, role.Result, content.Provider, content.Username, user.MainUserId, user.NickName, version, user.IdRef, mainUserIdRef);
                    var tokenHandler = new JwtSecurityTokenHandler();
                    accessToken = tokenHandler.WriteToken(tokenHandler.CreateToken(token));

                    var operatorToken = Guid.NewGuid().ToString();
                    SaveToken(user, accessToken, operatorToken, content);

                    activity?.SetStatus(ActivityStatusCode.Ok);
                    _loginSuccessCounter.Add(1);

                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = new TokenModel()
                        {
                            OperatorToken = operatorToken,
                            AccessToken = accessToken
                        }
                    };
                }
                catch (Exception ex)
                {
                    activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                    _loginFailureCounter.Add(1);

                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Error,
                        Message = ex.Message,
                        Result = null
                    };
                }
        }

        public async Task<BaseResponse<bool>> Logout(string token, bool isOperator = false)
        {
            using (var activity = _activitySource.StartActivity("logout"))
            {

                if (string.IsNullOrWhiteSpace(token))
                {
                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = true
                    };
                }

                _memCache.DeleteCache($"ot:{token}");

                var userId = string.Empty;
                var tokenEntity = new AppToken();

                if (isOperator)
                {
                    tokenEntity = _authContext.UserTokens.Where(x => x.OperatorToken == token).FirstOrDefault();
                    userId = tokenEntity != null ? tokenEntity.UserId : "";
                }
                else
                {
                    var parsedToken = JwtParser.ParseClaimsFromJwt(token).ToList();
                    var provider = parsedToken.Where(x => x.Type == "Provider").Select(x => x.Value).FirstOrDefault();
                    userId = parsedToken.Where(x => x.Type == "UserId").Select(x => x.Value).FirstOrDefault();

                    tokenEntity = _authContext.UserTokens.Where(x => x.UserId == userId).FirstOrDefault();
                }

                activity?.SetTag("user.id", userId);

                if (tokenEntity == null)
                {
                    return new BaseResponse<bool>
                    {
                        StatusCode = StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = true
                    };
                }

                using (var scope = new TransactionScope(TransactionScopeOption.Required, new System.Transactions.TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }))
                {
                    var accessToken = tokenEntity.Value;
                    _authContext.UserTokens.Remove(tokenEntity);
                    _authContext.SaveChanges();
                    scope.Complete();
                }

                activity?.SetStatus(ActivityStatusCode.Ok);

                return new BaseResponse<bool>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = true
                };
            }
        }

        public BaseResponse<TokenModel> Authenticate(string token)
        {
            using (var activity = _activitySource.StartActivity("authenticate"))
            {
                activity?.SetTag("token", token);

                try
                {
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

                    var validationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(TokenKey),
                        ValidateIssuer = true,
                        ValidIssuer = Issuer,
                        ValidateAudience = true,
                        ValidAudience = Issuer,
                        ValidateLifetime = false,
                        ClockSkew = TimeSpan.Zero
                    };

                    try
                    {
                        handler.ValidateToken(token, validationParameters, out SecurityToken jwtToken);
                    }
                    catch (Exception ex)
                    {
                        activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                        return new BaseResponse<TokenModel>
                        {
                            StatusCode = StatusCode.Unauthorized,
                            Message = "Invalid Token.",
                            Result = null
                        };
                    }

                    var parsedToken = JwtParser.ParseClaimsFromJwt(token).ToList();
                    var provider = parsedToken.Where(x => x.Type == "Provider").Select(x => x.Value).FirstOrDefault();
                    var tokenName = parsedToken.Where(x => x.Type == "TokenName").Select(x => x.Value).FirstOrDefault();
                    var userId = parsedToken.Where(x => x.Type == "UserId").Select(x => x.Value).FirstOrDefault();
                    var operatorToken = parsedToken.Where(x => x.Type == "UserToken").Select(x => x.Value).FirstOrDefault();

                    activity?.SetTag("parsed.user.id", userId);
                    activity?.SetTag("parsed.operator.token", operatorToken);
                    activity?.SetTag("parsed.provider", provider);

                    using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }))
                    {
                        var userToken = _authContext.UserTokens.AsNoTracking().FirstOrDefault(x => x.UserId == userId && x.LoginProvider == provider && x.Name == tokenName);
                        activity?.AddEvent(new ActivityEvent("fetched.db.token"));

                        if (userToken == null)
                        {
                            activity?.SetTag("auth.error", "null userToken");
                            activity?.SetStatus(ActivityStatusCode.Error);
                            return new BaseResponse<TokenModel>
                            {
                                StatusCode = StatusCode.Unauthorized,
                                Message = "Invalid Token.",
                                Result = null
                            };
                        }

                        activity?.SetTag("db.user.token", userToken.Value);

                        if (string.IsNullOrEmpty(operatorToken) && userToken.Value.Split(".")[1] != token.Split(".")[1])
                        {
                            activity?.SetTag("auth.error", "userToken.Value!=token");
                            activity?.SetStatus(ActivityStatusCode.Error);
                            return new BaseResponse<TokenModel>
                            {
                                StatusCode = StatusCode.Unauthorized,
                                Message = "Invalid Token.",
                                Result = null
                            };
                        }
                        //todo: use this in BO validation
                        if (!string.IsNullOrEmpty(operatorToken) && userToken.OperatorToken != operatorToken)
                        {
                            activity?.SetTag("auth.error", "userToken.OperatorToken!=operatorToken");
                            activity?.SetStatus(ActivityStatusCode.Error);
                            return new BaseResponse<TokenModel>
                            {
                                StatusCode = StatusCode.Unauthorized,
                                Message = "Invalid Token.",
                                Result = null
                            };
                        }

                        var user = _authContext.Users.AsNoTracking().FirstOrDefault(x => x.Id == userId);
                        if (user.LockoutEnd != null)
                        {
                            activity?.SetTag("auth.error", "user.lockoutEnd!=null");
                            activity?.SetStatus(ActivityStatusCode.Error);
                            return new BaseResponse<TokenModel>
                            {
                                StatusCode = StatusCode.Unauthorized,
                                Message = "Invalid Token.",
                                Result = null
                            };
                        }

                        if (userToken.SessionExpirationDate < DateTime.UtcNow)
                        {
                            activity?.SetTag("auth.error", "Session Expired");
                            activity?.SetStatus(ActivityStatusCode.Error);
                            return new BaseResponse<TokenModel>
                            {
                                StatusCode = StatusCode.Unauthorized,
                                Message = "Session Expired.",
                                Result = null
                            };
                            //var currentUserToken = _authContext.UserTokens.Where(x => x.UserId == userId && x.LoginProvider == provider).FirstOrDefault();

                            //userToken.SessionExpirationDate = DateTime.UtcNow.AddSeconds(_sessionExpirationInSeconds);
                            //activity?.AddEvent(new ActivityEvent("user.tokens.update"));

                            //_authContext.UserTokens.Update(userToken);
                            //_authContext.SaveChanges();
                        }

                        scope.Complete();
                        activity?.SetStatus(ActivityStatusCode.Ok);

                        return new BaseResponse<TokenModel>
                        {
                            StatusCode = StatusCode.Success,
                            Message = StatusCode.Success.ToString(),
                            Result = new TokenModel()
                            {
                                OperatorToken = userToken.OperatorToken ?? "",
                                AccessToken = userToken.Value
                            }
                        };
                    }
                    ;
                }
                catch (Exception ex)
                {
                    activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Error,
                        Message = ex.Message,
                        Result = null
                    };
                }
            }
        }

        public OperatorBaseResponse<object> AuthenticateOperator(string token, string? appId, bool isAgent = false)
        {
            using (var activity = _activitySource.StartActivity("authenticate-operator"))
            {
                var cache = _memCache.GetCache<AppToken>($"ot:{token}");
                var userType = isAgent ? "UserIdRef" : "UserId";

                if (cache != null)
                {
                    var parsedToken = JwtParser.ParseClaimsFromJwt(cache.Value).ToList();
                    var userId = parsedToken.FirstOrDefault(x => x.Type == userType).Value;
                    var tokenName = parsedToken.FirstOrDefault(x => x.Type == "TokenName")?.Value ?? string.Empty;
                    var nickName = parsedToken.FirstOrDefault(x => x.Type == "NickName")?.Value ?? string.Empty;
                    var roleName = parsedToken.FirstOrDefault(x => x.Type == "RoleName")?.Value ?? string.Empty;

                    activity?.Stop();

                    return new OperatorBaseResponse<object>
                    {
                        StatusCode = (int)StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = new
                        {
                            UserId = userId.ToString(),
                            UserName = tokenName,
                            NickName = nickName ?? tokenName,
                            RoleName = roleName ?? string.Empty,
                        }
                    };
                }

                try
                {
                    using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }))
                    {
                        var userToken = _authContext.UserTokens.AsNoTracking().Where(x => x.OperatorToken == token).FirstOrDefault();

                        if (userToken == null)
                        {
                            return new OperatorBaseResponse<object>
                            {
                                StatusCode = (int)StatusCode.Unauthorized,
                                Message = StatusCode.Unauthorized.ToString(),
                                Result = null
                            };
                        }

                        if (appId != null && userToken.LoginProvider != appId)
                        {
                            return new OperatorBaseResponse<object>
                            {
                                StatusCode = (int)StatusCode.Unauthorized,
                                Message = StatusCode.Unauthorized.ToString(),
                                Result = null
                            };
                        }

                        if (userToken.SessionExpirationDate < DateTime.UtcNow)
                        {
                            var currentUserToken = _authContext.UserTokens.Where(x => x.OperatorToken == token).FirstOrDefault();

                            currentUserToken.SessionExpirationDate = DateTime.UtcNow.AddMonths(_sessionExpirationInMonths);

                            _authContext.UserTokens.Update(currentUserToken);
                            _authContext.SaveChanges();
                        }

                        scope.Complete();
                        activity?.SetStatus(ActivityStatusCode.Ok);

                        if (string.IsNullOrEmpty(userToken.Value) && userToken.LoginProvider == $"{(int)Application.ClientChecklist}")
                        {
                            return new OperatorBaseResponse<object>
                            {
                                StatusCode = (int)StatusCode.Success,
                                Message = StatusCode.Success.ToString(),
                                Result = new
                                {
                                    UserId = userToken.UserId,
                                    UserName = userToken.Name,
                                    NickName = userToken.Name
                                }
                            };
                        }

                        var parsedToken = JwtParser.ParseClaimsFromJwt(userToken.Value).ToList();
                        var userId = parsedToken.FirstOrDefault(x => x.Type == userType)?.Value;
                        var tokenName = parsedToken.FirstOrDefault(x => x.Type == "TokenName")?.Value;
                        var nickName = parsedToken.FirstOrDefault(x => x.Type == "NickName")?.Value;
                        var roleName = parsedToken.FirstOrDefault(x => x.Type == "RoleName")?.Value;

                        return new OperatorBaseResponse<object>
                        {
                            StatusCode = (int)StatusCode.Success,
                            Message = StatusCode.Success.ToString(),
                            Result = new
                            {
                                UserId = userId,
                                UserName = tokenName,
                                NickName = nickName ?? tokenName,
                                RoleName = roleName ?? string.Empty
                            }
                        };
                    }
                    ;
                }
                catch (Exception ex)
                {
                    activity?.SetStatus(ActivityStatusCode.Error, ex.Message);

                    return new OperatorBaseResponse<object>
                    {
                        StatusCode = (int)StatusCode.Error,
                        Message = ex.Message,
                        Result = null
                    };
                }
            }
        }

        public async Task<BaseResponse<TokenModel>> AuthenticateSecurityCode(AuthenticateSecurityCodeRequest request)
        {
            try
            {
                var user = await _userManager.Users.FirstOrDefaultAsync(u => u.IdRef == request.IdRef);

                if (user == null)
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = "User does not exist.",
                        Result = null
                    };
                }

                if (user.LockoutEnd != null)
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = "User is locked.",
                        Result = null
                    };
                }

                var aspNetUserToken = _authContext.UserTokens.FirstOrDefault(x => x.UserId == user.Id);

                if (aspNetUserToken == null)
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Unauthorized,
                        Message = "Expired Token.",
                        Result = null
                    };
                }

                //TODO: verify security code

                return new BaseResponse<TokenModel>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = new TokenModel()
                    {
                        OperatorToken = aspNetUserToken.OperatorToken,
                        AccessToken = aspNetUserToken.Value
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
        public async Task<BaseResponse<PermissionResponse>> GetPermissionList(bool isSubUserOnly, int version, string categories = "0,1,2")
        {
            // 0 = all backoffice version
            // 1 = backoffice version 1
            // 2 = backoffice version 2
            var versions = new List<int>() { 0, 1, 2 };
            if (version > 0)
            {
                versions = new List<int>() { 0, version };
            }

            var categoryIds = categories.Split(',').ToList();

            var query = _authContext.Permission.Where(c => versions.Contains(c.Version) && categoryIds.Contains(c.CategoryId.ToString()));

            if (isSubUserOnly)
                query = query.Where(c => c.IsSubUser == isSubUserOnly);

            var result = query.ToList();

            var permList = result.Select(s => new PermissionModel()
            {
                Id = s.PermissionId.ToString(),
                CategoryId = s.CategoryId,
                CategoryName = s.CategoryName,
                SubCategoryName = s.SubCategoryName,
                GroupName = s.GroupName,
                Name = s.Name,
                ClaimType = s.ClaimType,
                HasReadOnly = s.HasReadOnly,
                SortOrder = s.SortOrder,
                IsSubUser = s.IsSubUser,
                UserGroupTemplateIdRef = s.UserGroupTemplateIdRef,
                Version = s.Version
            }).OrderBy(o => o.CategoryName).ThenBy(o => o.SortOrder).ToList();

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

        public async Task<BaseResponse<ActivityLogResponse>> GetActivityLogList(string userId, string search, MetaData metaData)
        {
            try
            {
                var result = new ActivityLogResponse();

                userId = GetUserId(userId);

                // for V2
                var activityLog = _authContext.ActivityLog.Where(x => x.UserId == userId).OrderByDescending(x => x.Date)
                    .Select(x => new ActivityLog
                    {
                        UserId = x.UserId,
                        Token = x.Token,
                        UserAgent = x.UserAgent,
                        IpAddress = x.IpAddress,
                        Country = x.Country,
                        Date = DateTime.Parse(x.Date.ToString())
                    }).ToList();
                //var activityLog = _authContext.ActivityLog.Where(x => x.UserId == userId).OrderByDescending(x => x.Date)
                //    .Select(x => new ActivityLog
                //    {
                //        UserId = x.UserId,
                //        Token = x.Token,
                //        BrowserInfo = x.BrowserInfo,
                //        BrowserVersion = x.BrowserVersion,
                //        OperatingSystem = x.OperatingSystem,
                //        IpAddress = x.IpAddress,
                //        Country = x.Country,
                //        Date = DateTime.Parse(x.Date.ToString())
                //    }).ToList();

                if (!string.IsNullOrWhiteSpace(search))
                {
                    activityLog = activityLog.Where(x =>
                    x.IpAddress.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                    x.Country.Contains(search, StringComparison.OrdinalIgnoreCase)).ToList();
                }

                var rowCount = activityLog.Count();
                var skip = metaData.PageSize == -1 ? 0 : (metaData.CurrentPage - 1) * metaData.PageSize;
                var totalPage = metaData.PageSize == -1 ? 0 : ((rowCount - 1) / metaData.PageSize) + 1;

                result.ActivityLogs = activityLog.Skip(skip).Take(metaData.PageSize == -1 ? rowCount : metaData.PageSize).ToList();
                result.MetaData = new MetaData()
                {
                    TotalCount = rowCount,
                    CurrentPage = metaData.CurrentPage,
                    PageSize = metaData.PageSize,
                    TotalPages = totalPage
                };

                return new BaseResponse<ActivityLogResponse>
                {
                    StatusCode = StatusCode.Success,
                    Message = StatusCode.Success.ToString(),
                    Result = result
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
        public async Task<BaseResponse<UsersOnlineResponse>> GetActiveSessions()
        {
            var userTokens = _authContext.UserTokens
                .Select(s => new
                {
                    UserId = s.UserId,
                    SessionExpirationDate = s.SessionExpirationDate
                }).ToList();

            var userIds = userTokens.Select(s => s.UserId).ToList();
            var filteredUserIds = userTokens.Where(c => userIds.Contains(c.UserId) && c.SessionExpirationDate > DateTime.UtcNow).Select(s => s.UserId).ToList();

            var userIdRefs = _authContext.Users.Where(x => filteredUserIds.Contains(x.Id)).Select(s => s.IdRef);

            return new BaseResponse<UsersOnlineResponse>()
            {
                StatusCode = StatusCode.Success,
                Message = StatusCode.Success.ToString(),
                Result = new UsersOnlineResponse()
                {
                    OnlineUsers = userIdRefs.ToList()
                }
            };
        }
        public string GetRemoteIpAddress(HttpContext httpContext)
        {
            var ip = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();

            if (string.IsNullOrEmpty(ip))
            {
                ip = httpContext.Connection.RemoteIpAddress.ToString();
            }

            return ip.Split(':').FirstOrDefault().Split(",").FirstOrDefault();
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
        private static string GetUserCountryByIp(string ip)
        {
            IpInfo ipInfo = new IpInfo();
            try
            {
                string info = new WebClient().DownloadString("http://ipinfo.io/" + ip);
                ipInfo = JsonSerializer.Deserialize<IpInfo>(info, new JsonSerializerOptions() { PropertyNameCaseInsensitive = true });
                RegionInfo myRI1 = new RegionInfo(ipInfo.Country);
                ipInfo.Country = myRI1.TwoLetterISORegionName;
            }
            catch (Exception)
            {
                ipInfo.Country = null;
            }

            return ipInfo.Country ?? "";
        }
        #endregion
    }
}
