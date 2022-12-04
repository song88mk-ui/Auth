using Auth.Api.Repositories;
using Auth.Shared.Models;
using Auth.Shared.Utilities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

namespace Auth.Api.ActionFilters
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class AuthorizeAttribute : Attribute, IAuthorizationFilter
    {
        private IConfiguration _configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json").Build();
        public async void OnAuthorization(AuthorizationFilterContext context)
        {
            var token = context.HttpContext.Request.Headers[HeaderNames.Authorization].ToString().Replace("Bearer ", "");
            var authRepository = (IAuthRepository)context.HttpContext.RequestServices.GetService(typeof(IAuthRepository));

            var validToken = await authRepository.Authenticate(token);

            if (validToken.Result.AccessToken != null)
            {
                context.Result = new JsonResult(new { Title = "Unauthorized", Message = validToken.Message }) { StatusCode = StatusCodes.Status401Unauthorized };
                return;
            }

            var claims = JwtParser.ParseClaimsFromJwt(token);
            var jsonData = JsonSerializer.Serialize(claims);
        }
    }
}
