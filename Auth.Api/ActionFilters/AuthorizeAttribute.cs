using Auth.Api.Repositories;
using Auth.Shared.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Net.Http.Headers;
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

            var validToken = await authRepository.Validate(token);

            if (!validToken.Result)
            {
                context.Result = new JsonResult(new { title = "Unauthorized", message = validToken.Message }) { StatusCode = StatusCodes.Status401Unauthorized };
                return;
            }
        }
    }
}
