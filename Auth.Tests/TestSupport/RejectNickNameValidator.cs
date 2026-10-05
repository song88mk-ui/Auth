using Auth.Shared.Models;
using Microsoft.AspNetCore.Identity;

namespace Auth.Tests.TestSupport
{
    /// <summary>
    /// Lets a test make UserManager.UpdateAsync fail on demand, so the error path after the update can be covered.
    /// </summary>
    public class RejectNickNameValidator : IUserValidator<AppUser>
    {
        public const string RejectedNickName = "rejected-nickname";
        public const string Description = "Nickname is not allowed.";

        public Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user)
        {
            return Task.FromResult(user.NickName == RejectedNickName
                ? IdentityResult.Failed(new IdentityError { Code = "RejectedNickName", Description = Description })
                : IdentityResult.Success);
        }
    }
}
