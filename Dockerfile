FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

WORKDIR /src

COPY Auth.Api Auth.Api
COPY Auth.Shared Auth.Shared

WORKDIR /src/Auth.Api

RUN dotnet restore
RUN dotnet build -c Release \
  --no-restore -o /app/build

RUN dotnet publish -c Release \
  --no-restore -o /app/publish /p:UseAppHost=false

RUN cd /app/publish && rm -f appsettings.*.json

FROM mcr.microsoft.com/dotnet/aspnet:6.0-alpine
RUN apk add --no-cache icu-libs
EXPOSE 80

WORKDIR /app

COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Auth.Api.dll"]
