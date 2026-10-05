using System.Runtime.Caching;
using Auth.Shared.Enums;
using Auth.Shared.Models;
using Auth.Shared.Models.Request;
using Auth.Tests.TestSupport;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Auth.Tests.Services
{
    public class AuthServiceTests : IDisposable
    {
        private readonly AuthTestHost _host = new();
        private readonly IdentityErrorDescriber _describer = new();

        public void Dispose() => _host.Dispose();

        #region GetAspNetSubAccountList

        [Fact]
        public async Task GetAspNetSubAccountList_ReturnsOnlySubAccountsOfMainUser_WithStatusAndJoinedClaims()
        {
            var main = await _host.CreateUserAsync("main");
            var otherMain = await _host.CreateUserAsync("othermain");
            var locked = await _host.CreateUserAsync("sub-locked", mainUserId: main.Id);
            var normal = await _host.CreateUserAsync("sub-normal", mainUserId: main.Id);
            await _host.CreateUserAsync("sub-other", mainUserId: otherMain.Id);

            locked.LockoutEnd = DateTimeOffset.UtcNow;
            await _host.UserManager.UpdateAsync(locked);

            var permission = _host.AddPermission("SBC.Reports");
            _host.AddUserClaim(locked, permission.PermissionId.ToString().ToUpper(), "2");
            _host.AddUserClaim(locked, "not-a-permission", "1");

            var response = await _host.AuthService.GetAspNetSubAccountList(new SubAccountListRequest { MainUserId = main.Id, Page = 1, PageSize = 10 });

            Assert.Equal(StatusCode.Success, response.StatusCode);
            var users = response.Result!.Users;
            Assert.Equal(new[] { "sub-locked", "sub-normal" }, users.Select(u => u.UserName).OrderBy(n => n));

            var lockedResponse = users.Single(u => u.UserName == "sub-locked");
            Assert.Equal("Locked", lockedResponse.Status);
            Assert.Equal(locked.Id, lockedResponse.UserId);
            Assert.Equal(main.Id, lockedResponse.MainUserId);
            Assert.Equal("sub-locked-nick", lockedResponse.NickName);
            Assert.Equal("sub-locked@example.com", lockedResponse.Email);
            var claim = Assert.Single(lockedResponse.Claims);
            Assert.Equal("SBC.Reports", claim.ClaimType);
            Assert.Equal("2", claim.ClaimValue);

            var normalResponse = users.Single(u => u.UserName == "sub-normal");
            Assert.Equal("Normal", normalResponse.Status);
            Assert.Empty(normalResponse.Claims);
        }

        [Fact]
        public async Task GetAspNetSubAccountList_PagesResultsAndFillsMetaData()
        {
            var main = await _host.CreateUserAsync("main");
            for (var i = 0; i < 3; i++)
                await _host.CreateUserAsync($"sub{i}", mainUserId: main.Id);

            var response = await _host.AuthService.GetAspNetSubAccountList(new SubAccountListRequest { MainUserId = main.Id, Page = 2, PageSize = 2 });

            var result = response.Result!;
            Assert.Single(result.Users);
            Assert.Equal(3, result.MetaData.TotalCount);
            Assert.Equal(2, result.MetaData.TotalPages);
            Assert.Equal(2, result.MetaData.CurrentPage);
            Assert.Equal(2, result.MetaData.PageSize);
        }

        [Fact]
        public async Task GetAspNetSubAccountList_FiltersBySearchTextOnUserNameOrNickName()
        {
            var main = await _host.CreateUserAsync("main");
            await _host.CreateUserAsync("alpha", mainUserId: main.Id);
            var beta = await _host.CreateUserAsync("beta", mainUserId: main.Id);
            beta.NickName = "findme";
            await _host.UserManager.UpdateAsync(beta);

            var byName = await _host.AuthService.GetAspNetSubAccountList(new SubAccountListRequest { MainUserId = main.Id, SearchText = "alp" });
            var byNick = await _host.AuthService.GetAspNetSubAccountList(new SubAccountListRequest { MainUserId = main.Id, SearchText = "findme" });

            Assert.Equal("alpha", Assert.Single(byName.Result!.Users).UserName);
            Assert.Equal("beta", Assert.Single(byNick.Result!.Users).UserName);
        }

        [Fact]
        public async Task GetAspNetSubAccountList_WithoutPaging_ReturnsNoUsersAndDefaultMetaData()
        {
            var main = await _host.CreateUserAsync("main");
            await _host.CreateUserAsync("sub", mainUserId: main.Id);

            var response = await _host.AuthService.GetAspNetSubAccountList(new SubAccountListRequest { MainUserId = main.Id, Page = 0, PageSize = 0 });

            Assert.Equal(StatusCode.Success, response.StatusCode);
            Assert.Empty(response.Result!.Users);
            Assert.Equal(0, response.Result.MetaData.TotalCount);
        }

        #endregion

        #region UpdateAspNetUsers

        [Fact]
        public async Task UpdateAspNetUsers_UnknownUser_ReturnsError()
        {
            var response = await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = "missing" });

            Assert.Equal(StatusCode.Error, response.StatusCode);
            Assert.Equal("User does not exist", response.Message);
            Assert.False(response.Result);
        }

        [Fact]
        public async Task UpdateAspNetUsers_ResolvesNumericUserIdByIdRef()
        {
            var user = await _host.CreateUserAsync("user", idRef: 12345);

            var response = await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = "12345", NickName = "renamed" });

            Assert.Equal(StatusCode.Success, response.StatusCode);
            Assert.Equal("renamed", (await _host.NewContext().Users.SingleAsync(u => u.Id == user.Id)).NickName);
        }

        [Theory]
        [InlineData(false, "new@example.com")]
        [InlineData(true, "user@example.com")]
        public async Task UpdateAspNetUsers_UpdatesEmailOnlyWhenNotDefault(bool isDefault, string expectedEmail)
        {
            var user = await _host.CreateUserAsync("user");

            var response = await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = user.Id, Email = "new@example.com" }, isDefault: isDefault);

            Assert.Equal(StatusCode.Success, response.StatusCode);
            var saved = await _host.NewContext().Users.SingleAsync(u => u.Id == user.Id);
            Assert.Equal(expectedEmail, saved.Email);
            Assert.Equal(!isDefault, saved.EmailConfirmed);
        }

        [Fact]
        public async Task UpdateAspNetUsers_LockingUserWithoutSession_SetsLockout()
        {
            var user = await _host.CreateUserAsync("user");

            var response = await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = user.Id, Status = "locked" });

            Assert.Equal(StatusCode.Success, response.StatusCode);
            Assert.NotNull((await _host.NewContext().Users.SingleAsync(u => u.Id == user.Id)).LockoutEnd);
        }

        // Current behaviour, kept as-is: the lock path loads the user's token with tracking, then ForceLogOutUsers
        // removes the same row loaded AsNoTracking, which EF rejects. The lock is saved and the cache entry cleared,
        // but the token row is not deleted and the caller gets an Error response.
        [Fact]
        public async Task UpdateAspNetUsers_LockingUserWithSession_SetsLockoutAndClearsCacheButFailsToLogOut()
        {
            var user = await _host.CreateUserAsync("user");
            _host.AddUserToken(user, "token-value");
            MemoryCache.Default.Set("ot:token-value", "cached", DateTimeOffset.UtcNow.AddMinutes(5));

            var response = await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = user.Id, Status = "locked" });

            Assert.Equal(StatusCode.Error, response.StatusCode);
            Assert.Contains("cannot be tracked", response.Message);
            using var context = _host.NewContext();
            Assert.NotNull((await context.Users.SingleAsync(u => u.Id == user.Id)).LockoutEnd);
            Assert.Null(MemoryCache.Default.Get("ot:token-value"));
            Assert.True(await context.UserTokens.AnyAsync(t => t.UserId == user.Id));
        }

        [Fact]
        public async Task UpdateAspNetUsers_NormalStatus_UnlocksUser()
        {
            var user = await _host.CreateUserAsync("user");
            user.LockoutEnd = DateTimeOffset.UtcNow;
            await _host.UserManager.UpdateAsync(user);

            await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = user.Id, Status = "Normal" });

            Assert.Null((await _host.NewContext().Users.SingleAsync(u => u.Id == user.Id)).LockoutEnd);
        }

        [Fact]
        public async Task UpdateAspNetUsers_RoleId_ReplacesRolesOfMainUserOnly()
        {
            await _host.CreateRoleAsync("Old");
            await _host.CreateRoleAsync("New");
            var main = await _host.CreateUserAsync("main", role: "Old");
            var sub = await _host.CreateUserAsync("sub", mainUserId: main.Id, role: "Old");

            await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = main.Id, RoleId = "x", RoleName = "New" });
            await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = sub.Id, RoleId = "x", RoleName = "New" });

            Assert.Equal(new[] { "New" }, await _host.UserManager.GetRolesAsync(main));
            Assert.Equal(new[] { "Old" }, await _host.UserManager.GetRolesAsync(sub));
        }

        [Fact]
        public async Task UpdateAspNetUsers_SubUser_ReplacesClaims()
        {
            var main = await _host.CreateUserAsync("main");
            var sub = await _host.CreateUserAsync("sub", mainUserId: main.Id);
            _host.AddUserClaim(sub, "old", "1");
            _host.AddUserClaim(main, "main-claim", "1");

            await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest
            {
                UserId = sub.Id,
                Claims = new List<ClaimModel> { new() { ClaimType = "new", ClaimValue = "2" } }
            });
            await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest
            {
                UserId = main.Id,
                Claims = new List<ClaimModel> { new() { ClaimType = "ignored", ClaimValue = "1" } }
            });

            var subClaims = await _host.UserManager.GetClaimsAsync(sub);
            var claim = Assert.Single(subClaims);
            Assert.Equal(("new", "2"), (claim.Type, claim.Value));
            Assert.Equal("main-claim", Assert.Single(await _host.UserManager.GetClaimsAsync(main)).Type);
        }

        [Fact]
        public async Task UpdateAspNetUsers_SubUserWithNoClaims_RemovesAllClaims()
        {
            var main = await _host.CreateUserAsync("main");
            var sub = await _host.CreateUserAsync("sub", mainUserId: main.Id);
            _host.AddUserClaim(sub, "old", "1");

            await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = sub.Id });

            Assert.Empty(await _host.UserManager.GetClaimsAsync(sub));
        }

        [Fact]
        public async Task UpdateAspNetUsers_PasswordWithoutOldPassword_ResetsPassword()
        {
            var user = await _host.CreateUserAsync("user");

            var response = await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = user.Id, Password = "NewPassw0rd" });

            Assert.Equal(StatusCode.Success, response.StatusCode);
            Assert.True(await _host.UserManager.CheckPasswordAsync(user, "NewPassw0rd"));
        }

        [Fact]
        public async Task UpdateAspNetUsers_ValidOldPassword_ChangesPassword()
        {
            var user = await _host.CreateUserAsync("user");

            var response = await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = user.Id, Password = "NewPassw0rd" }, AuthTestHost.DefaultPassword);

            Assert.Equal(StatusCode.Success, response.StatusCode);
            Assert.True(await _host.UserManager.CheckPasswordAsync(user, "NewPassw0rd"));
        }

        [Fact]
        public async Task UpdateAspNetUsers_NewPasswordSameAsOld_ReturnsErrorAndKeepsPassword()
        {
            var user = await _host.CreateUserAsync("user");

            var response = await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = user.Id, Password = AuthTestHost.DefaultPassword }, AuthTestHost.DefaultPassword);

            Assert.Equal(StatusCode.Error, response.StatusCode);
            Assert.Equal("Sorry, you entered an old password. Please choose a password you haven't used before.", response.Message);
            Assert.True(await _host.UserManager.CheckPasswordAsync(user, AuthTestHost.DefaultPassword));
        }

        [Fact]
        public async Task UpdateAspNetUsers_WrongOldPassword_ReturnsIdentityError()
        {
            var user = await _host.CreateUserAsync("user");
            _host.AddUserToken(user, "token-value");

            var response = await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = user.Id, Password = "NewPassw0rd" }, "WrongPassw0rd");

            Assert.Equal(StatusCode.Error, response.StatusCode);
            Assert.Equal(_describer.PasswordMismatch().Description, response.Message);
            Assert.True(await _host.NewContext().UserTokens.AnyAsync(t => t.UserId == user.Id));
        }

        [Fact]
        public async Task UpdateAspNetUsers_WeakPassword_ReturnsAllErrorsCommaSeparated()
        {
            var user = await _host.CreateUserAsync("user");

            var response = await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = user.Id, Password = "abc" });

            var expected = string.Join(",", new[]
            {
                _describer.PasswordTooShort(8),
                _describer.PasswordRequiresDigit(),
                _describer.PasswordRequiresUpper()
            }.Select(e => e.Description));
            Assert.Equal(StatusCode.Error, response.StatusCode);
            Assert.Equal(expected, response.Message);
        }

        [Fact]
        public async Task UpdateAspNetUsers_UpdateRejected_ReturnsErrorWithTrailingSpace()
        {
            var user = await _host.CreateUserAsync("user");

            var response = await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = user.Id, NickName = RejectNickNameValidator.RejectedNickName });

            Assert.Equal(StatusCode.Error, response.StatusCode);
            Assert.Equal($"{RejectNickNameValidator.Description} ", response.Message);
        }

        [Fact]
        public async Task UpdateAspNetUsers_Success_LogsOutUser()
        {
            var user = await _host.CreateUserAsync("user");
            var other = await _host.CreateUserAsync("other");
            _host.AddUserToken(user, "token-user");
            _host.AddUserToken(other, "token-other");

            var response = await _host.AuthService.UpdateAspNetUsers(new UserRegisterRequest { UserId = user.Id });

            Assert.Equal(StatusCode.Success, response.StatusCode);
            Assert.True(response.Result);
            using var context = _host.NewContext();
            Assert.False(await context.UserTokens.AnyAsync(t => t.UserId == user.Id));
            Assert.True(await context.UserTokens.AnyAsync(t => t.UserId == other.Id));
        }

        #endregion

        #region AddOrUpdateAspNetRoles

        [Fact]
        public async Task AddOrUpdateAspNetRoles_NewRole_CreatesRoleWithClaims()
        {
            var response = await _host.AuthService.AddOrUpdateAspNetRoles(new UserGroupRequest
            {
                UserGroupId = Guid.NewGuid().ToString(),
                UserGroupName = "Ops",
                Claims = new List<ClaimModel> { new() { ClaimType = "p1", ClaimValue = "1" }, new() { ClaimType = "p2", ClaimValue = "0" } }
            });

            Assert.Equal(StatusCode.Success, response.StatusCode);
            var role = await _host.RoleManager.FindByNameAsync("Ops");
            Assert.NotNull(role);
            Assert.True(role.UserGroupIdRef > 0);
            Assert.Equal(role.Id, response.Result!.UserGroupId);
            Assert.Equal("Ops", response.Result.UserGroupName);
            Assert.Equal(2, response.Result.Claims.Count);

            var claims = await _host.NewContext().RoleClaims.Where(c => c.RoleId == role.Id).OrderBy(c => c.ClaimType).ToListAsync();
            Assert.Equal(new[] { ("p1", "1"), ("p2", "0") }, claims.Select(c => (c.ClaimType!, c.ClaimValue!)));
        }

        [Fact]
        public async Task AddOrUpdateAspNetRoles_ExistingRole_RenamesAndUpsertsClaims()
        {
            var role = await _host.CreateRoleAsync("Ops");
            AddRoleClaim(role.Id, "changed", "1");
            AddRoleClaim(role.Id, "same", "2");
            AddRoleClaim(role.Id, "untouched", "1");

            var response = await _host.AuthService.AddOrUpdateAspNetRoles(new UserGroupRequest
            {
                UserGroupId = role.Id,
                UserGroupName = "Operations",
                Claims = new List<ClaimModel>
                {
                    new() { ClaimType = "changed", ClaimValue = "3" },
                    new() { ClaimType = "same", ClaimValue = "2" },
                    new() { ClaimType = "added", ClaimValue = "1" }
                }
            });

            Assert.Equal(StatusCode.Success, response.StatusCode);
            Assert.Equal("Operations", (await _host.NewContext().Roles.SingleAsync(r => r.Id == role.Id)).Name);
            var claims = await _host.NewContext().RoleClaims.Where(c => c.RoleId == role.Id).OrderBy(c => c.ClaimType).ToListAsync();
            Assert.Equal(new[] { ("added", "1"), ("changed", "3"), ("same", "2"), ("untouched", "1") }, claims.Select(c => (c.ClaimType!, c.ClaimValue!)));
        }

        [Theory]
        [InlineData("0", "0")]
        [InlineData("2", "2")]
        [InlineData("1", "1")]
        public async Task AddOrUpdateAspNetRoles_RestrictingClaim_CascadesToSubUserClaimsWithFullAccess(string newValue, string expectedSubUserValue)
        {
            var role = await _host.CreateRoleAsync("Ops");
            var subA = await _host.CreateUserAsync("subA");
            var subB = await _host.CreateUserAsync("subB");
            _host.AddUserClaim(subA, "p1", "1");
            _host.AddUserClaim(subB, "p1", "2");
            _host.AddUserClaim(subB, "p2", "1");

            await _host.AuthService.AddOrUpdateAspNetRoles(new UserGroupRequest
            {
                UserGroupId = role.Id,
                UserGroupName = "Ops",
                Claims = new List<ClaimModel> { new() { ClaimType = "p1", ClaimValue = newValue } }
            });

            var claims = await _host.NewContext().UserClaims.ToListAsync();
            Assert.Equal(expectedSubUserValue, claims.Single(c => c.UserId == subA.Id && c.ClaimType == "p1").ClaimValue);
            Assert.Equal("2", claims.Single(c => c.UserId == subB.Id && c.ClaimType == "p1").ClaimValue);
            Assert.Equal("1", claims.Single(c => c.UserId == subB.Id && c.ClaimType == "p2").ClaimValue);
        }

        [Fact]
        public async Task AddOrUpdateAspNetRoles_LogsOutUsersInRoleOnly()
        {
            await _host.CreateRoleAsync("Ops");
            await _host.CreateRoleAsync("Other");
            var inRole = await _host.CreateUserAsync("inrole", role: "Ops");
            var notInRole = await _host.CreateUserAsync("notinrole", role: "Other");
            _host.AddUserToken(inRole, "token-in");
            _host.AddUserToken(notInRole, "token-out");
            var role = await _host.RoleManager.FindByNameAsync("Ops");

            await _host.AuthService.AddOrUpdateAspNetRoles(new UserGroupRequest { UserGroupId = role!.Id, UserGroupName = "Ops" });

            using var context = _host.NewContext();
            Assert.False(await context.UserTokens.AnyAsync(t => t.UserId == inRole.Id));
            Assert.True(await context.UserTokens.AnyAsync(t => t.UserId == notInRole.Id));
        }

        [Fact]
        public async Task AddOrUpdateAspNetRoles_DuplicateName_ReturnsErrorWithTrailingSpace()
        {
            await _host.CreateRoleAsync("Ops");

            var response = await _host.AuthService.AddOrUpdateAspNetRoles(new UserGroupRequest
            {
                UserGroupId = Guid.NewGuid().ToString(),
                UserGroupName = "Ops"
            });

            Assert.Equal(StatusCode.Error, response.StatusCode);
            Assert.Equal($"{_describer.DuplicateRoleName("Ops").Description} ", response.Message);
        }

        private void AddRoleClaim(string roleId, string claimType, string value)
        {
            using var context = _host.NewContext();
            context.RoleClaims.Add(new IdentityRoleClaim<string> { RoleId = roleId, ClaimType = claimType, ClaimValue = value });
            context.SaveChanges();
        }

        #endregion

        #region GetAspNetUsersRole

        [Fact]
        public async Task GetAspNetUsersRole_ReturnsRoleOfUser()
        {
            var role = await _host.CreateRoleAsync("Ops");
            var user = await _host.CreateUserAsync("user", role: "Ops");

            var result = await _host.AuthService.GetAspNetUsersRole(user);

            Assert.Equal(role.Id, result.Id);
            Assert.Equal("Ops", result.Name);
        }

        [Fact]
        public async Task GetAspNetUsersRole_UserWithoutRole_ReturnsEmptyRole()
        {
            var role = await _host.CreateRoleAsync("Ops");
            var user = await _host.CreateUserAsync("user");

            var result = await _host.AuthService.GetAspNetUsersRole(user);

            // RoleModel is an IdentityRole, whose constructor generates a new Id
            Assert.NotEqual(role.Id, result.Id);
            Assert.Null(result.Name);
        }

        #endregion
    }
}
