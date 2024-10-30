using Auth.Api.Repositories;
using Auth.Shared.Enums;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
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
            var httpContext = context.HttpContext;

            var appIdHeaderRequest = httpContext.Request.Headers["x-app-id"].FirstOrDefault();
            var authRepository = httpContext.RequestServices.GetService(typeof(IAuthRepository)) as IAuthRepository;

            if (appIdHeaderRequest != null && appIdHeaderRequest == $"{(int)Application.ClientChecklist}")
            {
                var operatorToken = httpContext.Request.Headers["x-operator-token"].FirstOrDefault();
                var validToken = authRepository.AuthenticateOperator(operatorToken, appIdHeaderRequest, false);

                if (validToken.StatusCode != (int)StatusCode.Success)
                {
                    context.Result = new JsonResult(new { StatusCode = HttpStatusCode.Unauthorized, Message = validToken.Message }) { StatusCode = StatusCodes.Status401Unauthorized };
                }
                return;
            }
            else if (!httpContext.Request.Headers.ContainsKey("Authorization"))
            {
                context.Result = new JsonResult(new { StatusCode = HttpStatusCode.Unauthorized, message = "Missing Authorization" }) { StatusCode = StatusCodes.Status401Unauthorized };
                return;
            }

            var token = httpContext.Request.Headers[HeaderNames.Authorization].ToString().Replace("Bearer ", "");



            // get the JWT bearer authentication scheme
            var scheme = JwtBearerDefaults.AuthenticationScheme;

            // validate the JWT token
            var result = context.HttpContext.AuthenticateAsync(scheme).Result;

            if (!result.Succeeded)
            {
                context.Result = new JsonResult(new { StatusCode = HttpStatusCode.Unauthorized, Message = "Unauthorized" }) { StatusCode = StatusCodes.Status401Unauthorized };
                return;
            }

            if (httpContext.Request.Headers.ContainsKey("x-app"))
            {
                var app = context.HttpContext.Request.Headers["x-app"].FirstOrDefault();

                if (app != "Consumer")
                {
                    context.Result = new JsonResult(new { StatusCode = HttpStatusCode.Unauthorized, Message = "Unauthorized" }) { StatusCode = StatusCodes.Status401Unauthorized };
                    return;
                }
            }
            else
            {
                var validToken = authRepository.Authenticate(token);

                if (validToken.Result?.AccessToken == null)
                {
                    context.Result = new JsonResult(new { StatusCode = HttpStatusCode.Unauthorized, Message = validToken.Message }) { StatusCode = StatusCodes.Status401Unauthorized };
                    return;
                }
            }
        }
    }
}
