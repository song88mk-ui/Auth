# Auth

Identity and token service for the song88 platform. It owns the JWT that **four other repos**
validate, so a change to token shape, signing key, or issuer breaks them silently. See
`../INTEGRATION-MAP.md` before touching the token path.

Deployed as `auth-api` in the `platform` namespace.

## Commands

```
dotnet build Auth.sln
dotnet test Auth.Tests/Auth.Tests.csproj
```

CI (`.github/workflows/ci.yml`) runs the test job **only on pull requests** (line 15), so a
push to `main` runs no tests. Restore needs the private feed and `NUGET_PASSWORD` (line 28).

## Stack

.NET 10 / C# 14, three projects:

| Project | SDK | Role |
|---|---|---|
| `Auth.Api` | Web | Controllers, filters, repositories |
| `Auth.Shared` | class library | `AuthContext`, entities, models, enums |
| `Auth.Tests` | class library | xUnit 2.5.3 |

- **Controller-based MVC**, not minimal APIs. `AuthController` is routed at `v1`,
  `UserController` at `v1/api/[controller]`.
- **ASP.NET Identity** over EF Core 10.0.11 + SQL Server. `AuthContext`
  (`Auth.Shared/Data/Auth/AuthContext.cs:15`) is an `IdentityDbContext` with custom
  `AppUser` / `AppRole` / `AppToken`.
- `AddDbContextPool<AuthContext>` bound to config key `Context:Auth` (`Auth.Api/Program.cs:46`).
- **JWT bearer** (`Microsoft.AspNetCore.Authentication.JwtBearer` 10.0.11) plus an
  `x-api-key` gate via `Auth.Api/ActionFilters/ApiKeyFilter.cs`.
- Serilog, OpenTelemetry, `Infra.Extensions.Telemetry` 0.1.0-3, Swashbuckle 6.5.0
  (+ Annotations, ReDoc).

## Conventions specific to this repo

- **`Auth.Tests` references `Auth.Shared`, not `Auth.Api`.** Nothing in the API project is
  under test today — the suite is a single file, `Auth.Tests/Utilities/JwtParserTests.cs`. Testing a
  controller or filter requires adding the project reference first.
- **There are no EF migrations.** `Auth.Shared` contains no EF `Migrations` folder; the schema lives
  in `../infrastructure/flyway/migrations/dev/V1__Baseline.sql` under the `-- Auth` section
  (lines 1-119). Do not scaffold migrations without deciding who owns the schema — Flyway
  currently does.
- Nullable warnings are broadly suppressed in `Auth.Api/Auth.Api.csproj` (`CS8618;CS8602;CS8604`).
  Do not treat their absence as evidence the code is null-safe.
- Uses `AddNewtonsoftJson` for MVC serialization while other repos use `System.Text.Json`.
  Check which serializer applies before reasoning about a payload shape.

## Downstream consumers — do not break these

| Consumer | What it depends on |
|---|---|
| `backoffice-final` | Typed client + `x-api-key` (`../backoffice-final/Backoffice.API/Startup.cs:84-88`); validates `jwtToken.Issuer` against its own config (`../backoffice-final/Backoffice.API/ActionFilter/AuthorizeAttribute.cs:40-42`) |
| `client-checklist` | `AuthRepository` with `x-api-key` (`../client-checklist/client-checklist.api/Client.Checklist.API/Program.cs:34-38`) |
| `platform-final` | `Platform.Operator.API` holds an `AuthAPIKey` |
| `api-bdd-tests` | `@auth-api` tagged features against `http://auth-api.platform.svc:3000` |

Auth's own `Auth.Api/appsettings.json` now uses placeholders for the signing key and API key
(`__JWT_KEY__`, `__SECURITY_API_KEY__`, commit d07a227, DEVOPS-378); the issuer is still a
literal there. The literal signing key and issuer remain committed in the `appsettings.json` of
backoffice-final and client-checklist, and the Auth API key in those two plus
`../platform-final/Platform/Platform.Operator.API/appsettings.json`. Changing any of them is a
coordinated, multi-repo change.

## Tooling notes

dotnet-claude-kit defaults do not match this repo: it uses **xUnit 2.5.3, not v3**, has no
central package management, and is controller-based rather than minimal API. See the root
`../CLAUDE.md` for the full override list.
