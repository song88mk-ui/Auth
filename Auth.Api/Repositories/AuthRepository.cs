using Auth.Api.Services;
using Auth.Shared.Data.Auth;
using Auth.Shared.Data.Auth.Entities;
using Auth.Shared.Enums;
using Auth.Shared.Models;
using Auth.Shared.Models.Response;
using Auth.Shared.Utilities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Transactions;
using UAParser;

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
            IMemCache memCache)
        {
            _authContext = authContext;
            _userManager = userManager;
            _configuration = config;
            _userIdentityService = userIdentityService;

            TokenKey = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
            Issuer = _configuration["JWT:Issuer"] ?? string.Empty;
            _memCache = memCache;
        }

        #endregion

        #region Methods

        private async Task<SecurityTokenDescriptor> GenerateToken(string userId, IdentityRole role, string provider, string name, string mainUserId, string nickname, long userIdRef = 0l, long mainUserIdRef = 0l)
        {
            var token = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(),
                TokenType = "Bearer",
                Expires = DateTime.UtcNow.AddMonths(3),
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

            var claims = new List<Claim>();
            Claim? clients = null;
            var hasAdmin = true;

            if (role != null && role.Name.ToLower() == "super admin")
            {
                claims = (from permissions in _authContext.Permission
                          select new Claim(permissions.ClaimType, "1", $"{permissions.HasReadOnly}.{permissions.SortOrder}")).ToList();

                clients = claims.Where(x => x.Type == Shared.Enums.ClaimTypes.SBC_Clients_Access.ToString().Replace('_', '.')).Select(x => new Claim(x.Type, "")).FirstOrDefault();
            }
            else
            {
                if (isSubUser)
                {
                    claims = (from userClaims in _authContext.UserClaims
                              join permissions in _authContext.Permission on userClaims.ClaimType equals permissions.PermissionId.ToString()
                              where userClaims.UserId == userId && userClaims.ClaimValue != "0" && permissions.IsSubUser == true
                              select new Claim(permissions.ClaimType, userClaims.ClaimValue, $"{permissions.HasReadOnly}.{permissions.SortOrder}")).ToList();

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
                              where roleClaims.ClaimValue != "0" && roles.UserId == userId
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
            var oldToken = _authContext.UserTokens.Where(x => x.UserId == user.Id).FirstOrDefault();
            var sessionExpirationDate = DateTime.UtcNow.AddSeconds(_sessionExpirationInSeconds);

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

            Task.Run(() =>
            {
                if (loginModel != null)
                {
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
                }
            });
        }

        public async Task<BaseResponse<TokenModel>> Login(LoginModel content, string userAgent = "")
        {
            try
            {
                if (content != null)
                {
                    if (!string.IsNullOrWhiteSpace(userAgent) && (string.IsNullOrEmpty(content.BrowserInfo) && string.IsNullOrEmpty(content.BrowserVersion) && string.IsNullOrEmpty(content.OperatingSystem) && string.IsNullOrEmpty(content.IpAddress) && string.IsNullOrEmpty(content.Country)))
                    {
                        var uaParser = Parser.GetDefault();
                        ClientInfo client = uaParser.Parse(userAgent);
                        content.BrowserInfo = client.UA.Family.ToString();
                        content.BrowserVersion = $"{client.UA.Major}.{client.UA.Minor}.{client.UA.Patch}";
                        content.OperatingSystem = client.OS.ToString();
                        content.IpAddress = GetIPAddress();
                        if (content.IpAddress == "::1")
                        {
                            content.IpAddress = Dns.GetHostEntry(Dns.GetHostName()).AddressList[1].ToString();
                        }
                        var country = GetUserCountryByIp(content.IpAddress);
                        if (country != null)
                        {
                            content.Country = country;
                        }
                    }
                }

                // if main user get from role claims
                // if sub user get from user claims
                var user = await _userManager.FindByNameAsync(content.Username);
                var mainUserIdRef = 0l;

                if (user == null)
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Username_Not_Found,
                        Message = "Sorry, we couldn’t find an account with that username. Please try again.",
                        Result = null
                    };
                }

                if (user.AppId.ToString() != content.Provider)
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
                        StatusCode = StatusCode.User_Is_Locked,
                        Message = "User is locked.",
                        Result = null
                    };
                }
                if (!string.IsNullOrEmpty(user.MainUserId) && user.MainUserId != "0")
                {
                    mainUserIdRef = _authContext.Users.FirstOrDefault(x => x.Id == user.MainUserId).IdRef;
                }

                if (_userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, content.Password) != PasswordVerificationResult.Success)
                {
                    return new BaseResponse<TokenModel>
                    {
                        StatusCode = StatusCode.Invalid_Password,
                        Message = "Invalid Password. Please try again.",
                        Result = null
                    };
                }

                var accessToken = string.Empty;

                var role = await _userIdentityService.GetCurrentUserRole(user);

                var token = await GenerateToken(user.Id, role.Result, content.Provider, content.Username, user.MainUserId, user.NickName, user.IdRef, mainUserIdRef);
                var tokenHandler = new JwtSecurityTokenHandler();
                accessToken = tokenHandler.WriteToken(tokenHandler.CreateToken(token));

                var operatorToken = Guid.NewGuid().ToString();
                SaveToken(user, accessToken, operatorToken, content);

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

            return new BaseResponse<bool>
            {
                StatusCode = StatusCode.Success,
                Message = StatusCode.Success.ToString(),
                Result = true
            };
        }
        public BaseResponse<TokenModel> Authenticate(string token)
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

                var parsedToken = JwtParser.ParseClaimsFromJwt(token).ToList();
                var provider = parsedToken.Where(x => x.Type == "Provider").Select(x => x.Value).FirstOrDefault();
                var userId = parsedToken.Where(x => x.Type == "UserId").Select(x => x.Value).FirstOrDefault();

                using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }))
                {
                    var userToken = _authContext.UserTokens.AsNoTracking().FirstOrDefault(x => x.UserId == userId && x.LoginProvider == provider);

                    if (userToken == null)
                    {
                        return new BaseResponse<TokenModel>
                        {
                            StatusCode = StatusCode.Unauthorized,
                            Message = "Invalid Token.",
                            Result = null
                        };
                    }

                    if (userToken.Value != token)
                    {
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
                        return new BaseResponse<TokenModel>
                        {
                            StatusCode = StatusCode.Unauthorized,
                            Message = "Invalid Token.",
                            Result = null
                        };
                    }

                    if (userToken.SessionExpirationDate < DateTime.UtcNow)
                    {
                        var currentUserToken = _authContext.UserTokens.Where(x => x.UserId == userId && x.LoginProvider == provider).FirstOrDefault();

                        currentUserToken.SessionExpirationDate = DateTime.UtcNow.AddSeconds(_sessionExpirationInSeconds);

                        _authContext.UserTokens.Update(currentUserToken);
                        _authContext.SaveChanges();

                    }

                    scope.Complete();

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
        public OperatorBaseResponse<object> AuthenticateOperator(string token, bool isAgent = false)
        {
            var cache = _memCache.GetCache<AppToken>($"ot:{token}");

            if (cache != null)
            {
                var parsedToken = JwtParser.ParseClaimsFromJwt(cache.Value).ToList();
                var result = string.Empty;

                if (isAgent)
                {
                    return new OperatorBaseResponse<object>
                    {
                        StatusCode = (int)StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = new
                        {
                            UserId = parsedToken.Where(x => x.Type == "UserIdRef").Select(x => x.Value).FirstOrDefault().ToString()
                        }
                    };
                }
                else
                {
                    return new OperatorBaseResponse<object>
                    {
                        StatusCode = (int)StatusCode.Success,
                        Message = StatusCode.Success.ToString(),
                        Result = new
                        {
                            UserId = parsedToken.Where(x => x.Type == "UserId").Select(x => x.Value).FirstOrDefault().ToString()
                        }
                    };
                }
            }

            try
            {
                using (var scope = new TransactionScope(TransactionScopeOption.Required, new System.Transactions.TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted }))
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

                    if (userToken.SessionExpirationDate < DateTime.UtcNow)
                    {
                        var currentUserToken = _authContext.UserTokens.Where(x => x.OperatorToken == token).FirstOrDefault();

                        currentUserToken.SessionExpirationDate = DateTime.UtcNow.AddSeconds(_sessionExpirationInSeconds);

                        _authContext.UserTokens.Update(currentUserToken);
                        _authContext.SaveChanges();
                    }

                    scope.Complete();

                    var parsedToken = JwtParser.ParseClaimsFromJwt(userToken.Value).ToList();
                    var result = string.Empty;

                    if (isAgent)
                    {
                        return new OperatorBaseResponse<object>
                        {
                            StatusCode = (int)StatusCode.Success,
                            Message = StatusCode.Success.ToString(),
                            Result = new
                            {
                                UserId = parsedToken.Where(x => x.Type == "UserIdRef").Select(x => x.Value).FirstOrDefault().ToString()
                            }
                        };
                    }
                    else
                    {
                        return new OperatorBaseResponse<object>
                        {
                            StatusCode = (int)StatusCode.Success,
                            Message = StatusCode.Success.ToString(),
                            Result = new
                            {
                                UserId = parsedToken.Where(x => x.Type == "UserId").Select(x => x.Value).FirstOrDefault().ToString()
                            }
                        };
                    }
                };
            }
            catch (Exception ex)
            {
                return new OperatorBaseResponse<object>
                {
                    StatusCode = (int)StatusCode.Error,
                    Message = ex.Message,
                    Result = null
                };
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

                var activityLog = _authContext.ActivityLog.Where(x => x.UserId == userId).OrderByDescending(x => x.Date)
                    .Select(x => new ActivityLogModel
                    {
                        UserId = x.UserId,
                        Token = x.Token,
                        BrowserInfo = x.BrowserInfo,
                        BrowserVersion = x.BrowserVersion,
                        OperatingSystem = x.OperatingSystem,
                        IpAddress = x.IpAddress,
                        Country = x.Country,
                        Date = DateTime.Parse(x.Date.ToString())
                    }).ToList();

                if (!string.IsNullOrWhiteSpace(search))
                {
                    activityLog = activityLog.Where(x =>
                    x.BrowserInfo.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                    x.BrowserVersion.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                    x.OperatingSystem.Contains(search, StringComparison.OrdinalIgnoreCase) ||
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
        public static string GetUserCountryByIp(string ip)
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

            return ipInfo.Country;
        }
        public string GetIPAddress()
        {
            String address = "";
            WebRequest request = WebRequest.Create("http://checkip.dyndns.org/");
            using (WebResponse response = request.GetResponse())
            using (StreamReader stream = new StreamReader(response.GetResponseStream()))
            {
                address = stream.ReadToEnd();
            }

            int first = address.IndexOf("Address: ") + 9;
            int last = address.LastIndexOf("</body>");
            address = address.Substring(first, last - first);

            return address;
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
        #endregion
    }
}
