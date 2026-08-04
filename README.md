# Authentication API

Contains the new code base for the Authentication API: an ASP.NET Core (.NET 8) REST
service that provides authentication and user management for the platform's web apps
(the Swagger doc describes it as "Authorization API for web apps"). It is built on
ASP.NET Core Identity backed by SQL Server (Entity Framework Core), issues JWT bearer
tokens, and protects all endpoints with an `x-api-key` request header.

## Solution Layout

| Project | Target | Purpose |
|---|---|---|
| `Auth.Api` | net8.0 | Web API host: controllers, action filters, DI, Swagger, telemetry |
| `Auth.Shared` | net6.0 | Class library: `AuthContext` (Identity DbContext), models, `AuthService`, `MemCache`, JWT helpers |

Key endpoints (see `Auth.Api/Controllers/`):

- `AuthController` (route `v1`): `POST v1/login`, `POST v1/authentication/access`,
  `POST v1/authentication/operator`, `POST v1/authentication/security`,
  `POST v1/logout`, `GET v1/online`
- `UserController` (route `v1/api/User`): register, modify, status update, user/permission/
  user-group/activity-log listing, report role URLs, client tokens
- `GET /healthz` - health check
- `GET /swagger` - Swagger UI (enabled in all environments)

## Prerequisites

- .NET 8 SDK (`Auth.Shared` also needs the .NET 6 targeting pack, installed with recent SDKs)
- SQL Server reachable from your machine (a local instance or a Docker container on port 1433)
- Access to the private GitHub Packages NuGet feed
  `https://nuget.pkg.github.com/FlyingCockatoo/index.json` - the project references the
  private package `Infra.Extensions.Telemetry`, so `dotnet restore` fails without this
  source configured. There is no `nuget.config` in the repo; add the source yourself,
  for example:

  ```
  dotnet nuget add source "https://nuget.pkg.github.com/FlyingCockatoo/index.json" \
    --name github --username <your-github-username> --password <a-github-PAT-with-read:packages>
  ```

- Docker (only if you want to build/run the container image)

## Configuration

Configuration lives in `Auth.Api/appsettings.json` and can be overridden per key with
environment variables using the standard ASP.NET Core double-underscore convention
(e.g. `Context__Auth`, `Security__ApiKey`). The keys that matter:

| Key | Used by | Meaning |
|---|---|---|
| `Context:Auth` | `Program.cs` (DbContext) | SQL Server connection string to the `Auth` database |
| `Security:ApiKey` | `ActionFilters/ApiKeyFilter.cs` | Value every request must send in the `x-api-key` header |
| `JWT:Key` | `Program.cs` | Symmetric signing key for issued/validated JWTs |
| `JWT:Issuer` | `Program.cs` | JWT issuer; also used as the valid audience |
| `Serilog` | logging | Console sink, configured from appsettings |
| `Telemetry:Enabled` / `Telemetry:Environment` | OpenTelemetry (`Infra.Extensions.Telemetry`) | Disabled by default |

Do not commit real credentials to `appsettings.json`. The checked-in file currently
contains environment connection strings and keys; for local work point `Context:Auth`
at your own SQL Server and prefer environment-variable overrides for anything secret.

Launch profiles (`Auth.Api/Properties/launchSettings.json`) set
`ASPNETCORE_ENVIRONMENT` to `Local` (profile `Local`) or `Development`
(profile `Auth.Api`). Note there is no `appsettings.Local.json`; the `Local` profile
falls back to the base `appsettings.json`.

## Database

The service expects a SQL Server database named `Auth` containing the ASP.NET Core
Identity schema (AspNetUsers, AspNetRoles, etc.) plus the custom tables mapped in
`Auth.Shared/Data/Auth/AuthContext.cs`: `ActivityLog`, `Permission`, `ReportRoles`.

There are no EF Core migrations or schema-creation scripts in this repository, and
`Program.cs` does not create the schema at startup - you need an existing `Auth`
database (e.g. a restored copy from a dev environment). A quick local SQL Server:

```
docker run -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=<your-password>" -p 1433:1433 -d mcr.microsoft.com/mssql/server:2022-latest
```

Then set `Context:Auth` to point at `127.0.0.1,1433` with `TrustServerCertificate=True`
(a commented-out local connection string of this shape exists in `appsettings.json`).

## Run Locally

```
dotnet restore Auth.sln
dotnet build Auth.sln
dotnet run --project Auth.Api --launch-profile Local
```

- The app listens on `http://localhost:5181` (both the `Local` and `Auth.Api` profiles)
  and opens Swagger UI at `http://localhost:5181/swagger`.
- IIS Express profile uses `http://localhost:40114`.
- HTTPS redirection is disabled (`app.UseHttpsRedirection()` is commented out); local
  traffic is plain HTTP.
- Smoke test without a database: `GET http://localhost:5181/healthz` should return `Healthy`.
- Calling any controller endpoint requires the header `x-api-key: <value of Security:ApiKey>`.
  `UserController` additionally requires the custom `[Authorize]` filter
  (`ActionFilters/AuthorizeAttribute.cs`), which validates `x-app-id` plus an
  `x-operator-token` or bearer token depending on the calling application.

### Run with Docker

The Dockerfile needs the NuGet feed password as a build arg (it configures the same
GitHub Packages source during restore):

```
docker build --build-arg NUGET_PASSWORD=<github-PAT-with-read:packages> -t auth-api .
docker run -p 8080:8080 -e Context__Auth="<connection-string>" auth-api
```

Notes:

- The image is based on `mcr.microsoft.com/dotnet/aspnet:8.0`, which listens on port
  8080 by default; the Dockerfile does not declare an `EXPOSE` or port override.
- The publish stage deletes `appsettings.<Environment>.json` files; only the base
  `appsettings.json` ships in the image, so environment-specific settings must come
  from environment variables.

## Tests

There is no test project in this repository (nothing in `Auth.sln` besides `Auth.Api`
and `Auth.Shared`, and no `*Test*` projects on disk). CI (`.github/workflows/ci.yml`)
only builds and pushes the Docker image to ECR (`platform-auth-api`); it runs no tests.

Until a test project exists, validation is manual:

1. `dotnet build Auth.sln` succeeds with no new warnings.
2. Run the app and exercise endpoints through Swagger UI (`/swagger`) with the
   `x-api-key` header set.
3. `GET /healthz` returns healthy.

## Dependent Services

| Dependency | Required locally | Notes |
|---|---|---|
| SQL Server (`Auth` database) | Yes | Configured via `Context:Auth`; schema must pre-exist (no migrations in repo) |
| GitHub Packages NuGet feed (FlyingCockatoo) | Yes, for restore | Hosts `Infra.Extensions.Telemetry` |
| OpenTelemetry collector | No | Telemetry is disabled by default (`Telemetry:Enabled=false`) |

## Security

Review the JWT (Json Web Token) security options during deployment (`JWT:Key`,
`JWT:Issuer`, token validation parameters in `Program.cs`). Also note:

- CORS is wide open (`AllowAnyOrigin/Method/Header` policy `AllowAllOrigins`).
- Swagger UI is served in every environment, including production builds.
- Rotate any keys or connection strings that have been committed to
  `appsettings.json` before production use.

## Keeping this README up to date

This README is part of the codebase. Update it in the same PR whenever anything it documents changes - project structure (projects/services added, renamed, or removed), configuration keys, run commands, ports, endpoints, or external dependencies. An outdated run guide is worse than none.
