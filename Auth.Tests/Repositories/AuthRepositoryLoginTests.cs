using System.IdentityModel.Tokens.Jwt;
using Auth.Shared.Enums;
using Auth.Shared.Models;
using Auth.Tests.TestSupport;
using Microsoft.EntityFrameworkCore;

namespace Auth.Tests.Repositories
{
    public class AuthRepositoryLoginTests : IDisposable
    {
        private const string Backoffice = "1001";
        private const string ClientChecklist = "1004";

        private readonly AuthTestHost _host = new();

        public void Dispose() => _host.Dispose();

        #region Login failures

        [Fact]
        public async Task Login_UnknownUser_ReturnsUsernameNotFound()
        {
            var response = await _host.AuthRepository.Login(LoginFor("nobody"), 0);

            Assert.Equal(StatusCode.Username_Not_Found, response.StatusCode);
            Assert.Equal("Sorry, we couldn’t find an account with that username. Please try again.", response.Message);
            Assert.Null(response.Result);
        }

        [Fact]
        public async Task Login_WrongProvider_ReturnsUnauthorized()
        {
            await _host.CreateUserAsync("user");

            var response = await _host.AuthRepository.Login(LoginFor("user", provider: ClientChecklist), 0);

            Assert.Equal(StatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("User does not exist.", response.Message);
        }

        [Fact]
        public async Task Login_LockedUser_ReturnsUserIsLocked()
        {
            var user = await _host.CreateUserAsync("user");
            user.LockoutEnd = DateTimeOffset.UtcNow;
            await _host.UserManager.UpdateAsync(user);

            var response = await _host.AuthRepository.Login(LoginFor("user"), 0);

            Assert.Equal(StatusCode.User_Is_Locked, response.StatusCode);
            Assert.Equal("User is locked.", response.Message);
        }

        [Fact]
        public async Task Login_WrongPassword_ReturnsInvalidPassword()
        {
            await _host.CreateUserAsync("user");

            var response = await _host.AuthRepository.Login(LoginFor("user", password: "WrongPassw0rd"), 0);

            Assert.Equal(StatusCode.Invalid_Password, response.StatusCode);
            Assert.Equal("Invalid Password. Please try again.", response.Message);
            Assert.False(await _host.NewContext().UserTokens.AnyAsync());
        }

        #endregion

        #region Login success and session

        [Fact]
        public async Task Login_MainUser_ReturnsTokenWithUserAndRoleClaims()
        {
            var role = await _host.CreateRoleAsync("Ops");
            var user = await _host.CreateUserAsync("user", idRef: 42, role: "Ops");

            var token = await LoginAndReadToken(LoginFor("user"), 0);

            Assert.Equal(user.Id, Claim(token, "UserId"));
            Assert.Equal("42", Claim(token, "UserIdRef"));
            Assert.Equal(Backoffice, Claim(token, "Provider"));
            Assert.Equal("user", Claim(token, "TokenName"));
            Assert.Equal("", Claim(token, "MainUserId"));
            Assert.Equal("0", Claim(token, "MainUserIdRef"));
            Assert.Equal("user-nick", Claim(token, "Nickname"));
            Assert.Equal(role.Id, Claim(token, "Permission"));
            Assert.Equal(role.Id, Claim(token, "RoleId"));
            Assert.Equal("Ops", Claim(token, "RoleName"));
            Assert.Equal(AuthTestHost.Issuer, token.Issuer);
            Assert.Equal(AuthTestHost.Issuer, Assert.Single(token.Audiences));
            Assert.InRange(token.ValidTo, DateTime.UtcNow.AddMonths(3).AddMinutes(-5), DateTime.UtcNow.AddMonths(3).AddMinutes(5));
        }

        [Fact]
        public async Task Login_UserWithoutRole_ReturnsEmptyRoleClaims()
        {
            await _host.CreateUserAsync("user");

            var token = await LoginAndReadToken(LoginFor("user"), 0);

            Assert.Equal("", Claim(token, "Permission"));
            Assert.Equal("", Claim(token, "RoleId"));
            Assert.Equal("", Claim(token, "RoleName"));
        }

        [Fact]
        public async Task Login_SavesSessionAndActivityLog()
        {
            var user = await _host.CreateUserAsync("user");

            var response = await _host.AuthRepository.Login(LoginFor("user", ipAddress: "10.0.0.1", country: "PH"), 0);

            Assert.Equal(StatusCode.Success, response.StatusCode);
            using var context = _host.NewContext();
            var session = await context.UserTokens.SingleAsync(t => t.UserId == user.Id);
            Assert.Equal(response.Result!.AccessToken, session.Value);
            Assert.Equal(response.Result.OperatorToken, session.OperatorToken);
            Assert.Equal(Backoffice, session.LoginProvider);
            Assert.Equal("user", session.Name);
            Assert.InRange(session.SessionExpirationDate, DateTime.UtcNow.AddMonths(3).AddMinutes(-5), DateTime.UtcNow.AddMonths(3).AddMinutes(5));

            var activity = await context.ActivityLog.SingleAsync(a => a.UserId == user.Id);
            Assert.Equal(response.Result.AccessToken, activity.Token);
            Assert.Equal("10.0.0.1", activity.IpAddress);
            Assert.Equal("PH", activity.Country);
            Assert.Equal("test-agent", activity.UserAgent);
        }

        [Fact]
        public async Task Login_Twice_UpdatesExistingSession()
        {
            var user = await _host.CreateUserAsync("user");

            await _host.AuthRepository.Login(LoginFor("user"), 0);
            var second = await _host.AuthRepository.Login(LoginFor("user"), 0);

            var session = await _host.NewContext().UserTokens.SingleAsync(t => t.UserId == user.Id);
            Assert.Equal(second.Result!.OperatorToken, session.OperatorToken);
            Assert.Equal(second.Result.AccessToken, session.Value);
        }

        [Fact]
        public async Task Login_WithoutIpAddressOrCountry_StoresEmptyCountry()
        {
            var user = await _host.CreateUserAsync("user");

            var login = LoginFor("user", ipAddress: "");
            login.Country = null!;

            var response = await _host.AuthRepository.Login(login, 0);

            Assert.Equal(StatusCode.Success, response.StatusCode);
            var activity = await _host.NewContext().ActivityLog.SingleAsync(a => a.UserId == user.Id);
            Assert.Equal("", activity.Country);
            Assert.Equal("", activity.IpAddress);
        }

        [Fact]
        public async Task Login_ClientChecklist_TokenAndSessionNeverExpire()
        {
            var user = await _host.CreateUserAsync("user", appId: (int)Application.ClientChecklist);

            var token = await LoginAndReadToken(LoginFor("user", provider: ClientChecklist), 0);

            Assert.Equal(9999, token.ValidTo.Year);
            Assert.Equal(DateTime.MaxValue, (await _host.NewContext().UserTokens.SingleAsync(t => t.UserId == user.Id)).SessionExpirationDate);
        }

        #endregion

        #region Permission claims (GenerateToken)

        [Theory]
        [InlineData(0, true)]
        [InlineData(1, true)]
        [InlineData(2, false)]
        public async Task Login_MainUser_AddsRoleClaimsFilteredByVersionCategoryAndValue(int version, bool includesVersion1Permission)
        {
            var role = await _host.CreateRoleAsync("Ops");
            await _host.CreateUserAsync("user", role: "Ops");
            _host.AddRoleClaim(role, _host.AddPermission("SBC.V0", version: 0, hasReadOnly: true, sortOrder: 3), "2");
            _host.AddRoleClaim(role, _host.AddPermission("SBC.V1", version: 1), "1");
            _host.AddRoleClaim(role, _host.AddPermission("SBC.V2", version: 2), "1");
            _host.AddRoleClaim(role, _host.AddPermission("Hidden.Category99", categoryId: 99), "1");
            _host.AddRoleClaim(role, _host.AddPermission("SBC.NoAccess"), "0");

            var token = await LoginAndReadToken(LoginFor("user"), version);

            Assert.Equal("2", Claim(token, "SBC.V0"));
            Assert.Equal("1", Claim(token, "SBC.V2"));
            Assert.Equal(includesVersion1Permission, HasClaim(token, "SBC.V1"));
            Assert.False(HasClaim(token, "Hidden.Category99"));
            Assert.False(HasClaim(token, "SBC.NoAccess"));
        }

        [Theory]
        [InlineData(true, false)]
        [InlineData(false, true)]
        public async Task Login_MainUser_RemovesSubUsersClaimOnlyWhenUserHasAdminPermission(bool hasAdmin, bool expectSubUsersClaim)
        {
            var role = await _host.CreateRoleAsync("Ops");
            await _host.CreateUserAsync("user", role: "Ops");
            _host.AddRoleClaim(role, _host.AddPermission("SBC.SubUsers"), "1");
            if (hasAdmin)
                _host.AddRoleClaim(role, _host.AddPermission("Admin.Users"), "1");

            var token = await LoginAndReadToken(LoginFor("user"), 0);

            Assert.Equal(expectSubUsersClaim, HasClaim(token, "SBC.SubUsers"));
            Assert.Equal(hasAdmin, HasClaim(token, "Admin.Users"));
        }

        [Fact]
        public async Task Login_MainUser_ReplacesClientsAccessClaimWithClientCodes()
        {
            var role = await _host.CreateRoleAsync("Ops");
            await _host.CreateUserAsync("user", role: "Ops");
            _host.AddRoleClaim(role, _host.AddPermission("SBC.Clients.Access"), "C1,C2");

            var token = await LoginAndReadToken(LoginFor("user"), 0);

            Assert.Equal("C1,C2", Claim(token, "ClientCodes"));
            Assert.False(HasClaim(token, "SBC.Clients.Access"));
        }

        [Fact]
        public async Task Login_SuperAdmin_GetsAllPermissionsWithFullAccessAndAllClients()
        {
            await _host.CreateRoleAsync("Super Admin");
            await _host.CreateUserAsync("admin", role: "Super Admin");
            _host.AddPermission("Admin.Users");
            _host.AddPermission("SBC.V1", version: 1);
            _host.AddPermission("SBC.Clients.Access");
            _host.AddPermission("SBC.SubUsers");
            _host.AddPermission("Hidden.Category99", categoryId: 99);

            var token = await LoginAndReadToken(LoginFor("admin"), 2);

            Assert.Equal("1", Claim(token, "Admin.Users"));
            Assert.Equal("1", Claim(token, "SBC.V1"));
            Assert.Equal("ALL", Claim(token, "ClientCodes"));
            // Current behaviour, kept as-is: the "ALL" clients claim is a new Claim instance, so claims.Remove(clients)
            // does not remove the original permission claim and super admin tokens carry both.
            Assert.Equal("1", Claim(token, "SBC.Clients.Access"));
            Assert.False(HasClaim(token, "SBC.SubUsers"));
            Assert.False(HasClaim(token, "Hidden.Category99"));
            Assert.Equal("Super Admin", Claim(token, "RoleName"));
        }

        [Fact]
        public async Task Login_SubUser_GetsOwnSubUserClaimsThatMatchMainUserRoleAndMainUserClients()
        {
            var role = await _host.CreateRoleAsync("Ops");
            var main = await _host.CreateUserAsync("main", idRef: 500, role: "Ops");
            var sub = await _host.CreateUserAsync("sub", mainUserId: main.Id, idRef: 501);

            var matching = _host.AddPermission("SBC.Reports", isSubUser: true);
            var valueMismatch = _host.AddPermission("SBC.Players", isSubUser: true);
            var notForSubUsers = _host.AddPermission("SBC.Settings", isSubUser: false);
            var notInMainRole = _host.AddPermission("SBC.Extra", isSubUser: true);
            var clients = _host.AddPermission("SBC.Clients.Access");

            _host.AddRoleClaim(role, matching, "1");
            _host.AddRoleClaim(role, valueMismatch, "2");
            _host.AddRoleClaim(role, notForSubUsers, "1");
            _host.AddRoleClaim(role, clients, "C1,C2");

            _host.AddUserClaim(sub, matching.PermissionId.ToString(), "1");
            _host.AddUserClaim(sub, valueMismatch.PermissionId.ToString(), "1");
            _host.AddUserClaim(sub, notForSubUsers.PermissionId.ToString(), "1");
            _host.AddUserClaim(sub, notInMainRole.PermissionId.ToString(), "1");

            var token = await LoginAndReadToken(LoginFor("sub"), 0);

            Assert.Equal("1", Claim(token, "SBC.Reports"));
            Assert.False(HasClaim(token, "SBC.Players"));
            Assert.False(HasClaim(token, "SBC.Settings"));
            Assert.False(HasClaim(token, "SBC.Extra"));
            Assert.Equal("C1,C2", Claim(token, "ClientCodes"));
            Assert.Equal(sub.Id, Claim(token, "UserId"));
            Assert.Equal(main.Id, Claim(token, "MainUserId"));
            Assert.Equal("500", Claim(token, "MainUserIdRef"));
            Assert.Equal(role.Id, Claim(token, "RoleId"));
            Assert.Equal("Ops", Claim(token, "RoleName"));
        }

        #endregion

        private static LoginModel LoginFor(string username, string password = AuthTestHost.DefaultPassword, string provider = Backoffice,
            string ipAddress = "10.0.0.1", string country = "PH")
        {
            return new LoginModel
            {
                Username = username,
                Password = password,
                Provider = provider,
                UserAgent = "test-agent",
                IpAddress = ipAddress,
                Country = country
            };
        }

        private async Task<JwtSecurityToken> LoginAndReadToken(LoginModel login, int version)
        {
            var response = await _host.AuthRepository.Login(login, version);
            Assert.True(response.StatusCode == StatusCode.Success, response.Message);
            return new JwtSecurityTokenHandler().ReadJwtToken(response.Result!.AccessToken);
        }

        private static string Claim(JwtSecurityToken token, string type) => Assert.Single(token.Claims, c => c.Type == type).Value;

        private static bool HasClaim(JwtSecurityToken token, string type) => token.Claims.Any(c => c.Type == type);
    }
}
