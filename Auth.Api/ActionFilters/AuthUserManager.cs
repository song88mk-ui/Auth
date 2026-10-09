using Auth.Shared.Data.Auth.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Auth.Api.ActionFilters
{
    public class AuthUserManager : UserManager<AspNetUsers>
    {
        public AuthUserManager(IUserStore<AspNetUsers> store, IOptions<IdentityOptions> optionsAccessor, IPasswordHasher<AspNetUsers> passwordHasher, IEnumerable<IUserValidator<AspNetUsers>> userValidators, IEnumerable<IPasswordValidator<AspNetUsers>> passwordValidators, ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, IServiceProvider services, ILogger<UserManager<AspNetUsers>> logger) : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
        }
    }
}
