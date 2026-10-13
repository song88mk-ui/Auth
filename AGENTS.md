# AGENTS.md — Auth

Identity and token service (`auth-api`): ASP.NET Identity over SQL Server, issues the JWT other
repos validate. Read [CLAUDE.md](CLAUDE.md) first: it holds the standing rules every agent follows
and the full operating manual. This file is the short version for agents.

## Mission boundaries
- Subject = Auth (login, tokens, users and permissions). It does not own the `Auth` schema: Flyway
  in `infrastructure` does.
- Only modify files inside this repo; siblings (`backoffice-final`, `client-checklist`,
  `platform-final`, `api-bdd-tests`, `infrastructure`, `argocd`) are read-only references.
- Controller-based MVC, not minimal APIs; dotnet-claude-kit defaults do not apply as-is.

## Hard rules
- Token shape, signing key, issuer and the `x-api-key` gate are a contract with four consumer repos;
  a change there breaks them silently (CLAUDE.md § Critical rules, consumer table).
- The signing key, issuer and Auth API key are duplicated in sibling `appsettings.json` files, so
  changing one is a coordinated multi-repo change (CLAUDE.md § Critical rules).
- No EF migrations: the schema lives in `infrastructure` Flyway `V1__Baseline.sql`. Do not scaffold
  migrations without deciding who owns the schema (CLAUDE.md § Critical rules).
- Tests are xUnit 2.5.3, not v3, with no central package management (CLAUDE.md § Conventions).
- CI runs tests only on pull requests; a push to `main` runs none (CLAUDE.md § Build / test).
- Nullable warnings are suppressed in `Auth.Api`; their absence is not proof of null safety
  (CLAUDE.md § Conventions).
- MVC uses Newtonsoft.Json, not System.Text.Json; check the serializer before reasoning about a
  payload shape (CLAUDE.md § Conventions).

## See also
[CLAUDE.md](CLAUDE.md) · [README.md](README.md) ·
[.claude/skills/jira-updates/SKILL.md](.claude/skills/jira-updates/SKILL.md)
