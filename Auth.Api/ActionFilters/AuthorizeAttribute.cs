using Auth.Api.Repositories;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Net.Http.Headers;
using System.Net;

namespace Auth.Api.ActionFilters
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class AuthorizeAttribute : Attribute, IAuthorizationFilter
    {
        private IConfiguration _configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json").Build();
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (!context.HttpContext.Request.Headers.ContainsKey("Authorization"))
            {
                context.Result = new JsonResult(new { StatusCode = HttpStatusCode.Unauthorized, message = "Missing Authorization" }) { StatusCode = StatusCodes.Status401Unauthorized };
                return;
            }

            var token = context.HttpContext.Request.Headers[HeaderNames.Authorization].ToString().Replace("Bearer ", "");
            var authRepository = context.HttpContext.RequestServices.GetService(typeof(IAuthRepository)) as IAuthRepository;

            var validToken = authRepository.Authenticate(token);

            if (validToken.Result?.AccessToken == null)
            {
                context.Result = new JsonResult(new { StatusCode = HttpStatusCode.Unauthorized, Message = validToken.Message }) { StatusCode = StatusCodes.Status401Unauthorized };
                return;
            }
        }
    }
}
