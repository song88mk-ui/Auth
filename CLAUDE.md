# CLAUDE.md — Auth

<!-- song88:standing-rules:begin -->
## Standing rules (every prompt, before anything else)

Shared by every song88 repo. The canonical text is `../song88-claude/standing-rules/STANDING-RULES.md`:
edit it there and run `../song88-claude/standing-rules/sync_standing_rules.py`, never edit this block by hand. A `UserPromptSubmit`
hook in `.claude/settings.json` re-injects these rules on every prompt.

1. **Read this repo's CLAUDE.md and AGENTS.md first.**
2. **Fetch latest before investigating.** Run `git fetch origin` and compare with origin/main for this repo and every sibling repo you read, before citing file contents or repo or deployment state as fact. A local checkout can be hundreds of commits behind. When you cannot or should not pull, read files with `git show origin/main:<path>`, and say so explicitly if you did not check.
3. **Trace in the code, never from memory.** Search the repo and its docs, trace the feature end to end, and cite `file:line`.
4. **Label every claim verified, assumption or unknown.** Never guess.
5. **Explain the plan and wait for approval before any code change.** Then make the smallest change that does the job.
6. **Production is read-only.** Do not run queries, deploy, change schema or invalidate caches unless explicitly instructed.
7. **Update docs and README in the same change** whenever the change affects what they describe.
8. **Every SQL script must be idempotent.** Re-running it is a no-op with the same end state.
9. **Do not modify a sibling repo as a side effect of work here.** Siblings are read-only references unless the user asks for a change in that repo.
10. **Never print, log or commit a secret.** Mask it if it must appear in a log line.
11. **A new project or service ships with tests** in the repo's existing test framework.
12. **Commit, push or open a PR only when explicitly asked.** "Implement it" authorizes local edits only.
13. **Report validation with every change:** build, unit tests, integration tests, manual checks and remaining risks. If something could not be validated, say what and why, name the tests to run before deployment, and mark the work Implementation Complete – Validation Pending, never Completed.
14. **If a workflow step does not apply, say so** instead of skipping it silently.
<!-- song88:standing-rules:end -->

## What this repo is

Identity and token service for the song88 platform. It owns the JWT that **four other repos**
validate, so a change to token shape, signing key, or issuer breaks them silently. See
`../INTEGRATION-MAP.md` before touching the token path.

Deployed as `auth-api` in the `platform` namespace. .NET 10 / C# 14, three projects:

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

## Build / test

```
dotnet build Auth.sln
dotnet test Auth.Tests/Auth.Tests.csproj
```

CI (`.github/workflows/ci.yml`) runs the test job **only on pull requests** (line 15), so a
push to `main` runs no tests. Restore needs the private feed and `NUGET_PASSWORD` (line 28).

## Critical rules

**Downstream consumers — do not break these.**

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

**There are no EF migrations.** `Auth.Shared` contains no EF `Migrations` folder; the schema lives
in `../infrastructure/flyway/migrations/dev/V1__Baseline.sql` under the `-- Auth` section
(lines 1-119). Do not scaffold migrations without deciding who owns the schema — Flyway
currently does.

## Conventions

- **`Auth.Tests` references both `Auth.Api` and `Auth.Shared`** (`Auth.Tests/Auth.Tests.csproj:24-25`).
  `TestSupport/AuthTestHost.cs` builds `AuthService` and `AuthRepository` as `Program.cs` does, on an
  EF Core in-memory database per test. Tests: `Utilities/JwtParserTests.cs`,
  `Services/AuthServiceTests.cs`, `Repositories/AuthRepositoryLoginTests.cs` (DEVOPS-378).
- Nullable warnings are broadly suppressed in `Auth.Api/Auth.Api.csproj` (`CS8618;CS8602;CS8604`).
  Do not treat their absence as evidence the code is null-safe.
- Uses `AddNewtonsoftJson` for MVC serialization while other repos use `System.Text.Json`.
  Check which serializer applies before reasoning about a payload shape.
- dotnet-claude-kit defaults do not match this repo: it uses **xUnit 2.5.3, not v3**, has no
  central package management, and is controller-based rather than minimal API.
- **Logging rules** (shared with odds-engine-2):
  - Pass the exception as the first argument: `_logger.LogError(ex, "... {Payload}", payload)`.
    Never put `ex.Message` or `ex.StackTrace` in the message text, and never pass the exception
    as a template argument.
  - Use PascalCase placeholders (`{Message}`, `{Payload}`).
  - Keep operational log lines (start, connecting, connected, progress). Do not remove or merge
    them to satisfy SonarQube S6664.

## See also

`../CLAUDE.md` (workspace, full dotnet-claude-kit override list) · `../INTEGRATION-MAP.md` ·
`.claude/README.md` · `.claude/skills/jira-updates/SKILL.md` · `AGENTS.md`
