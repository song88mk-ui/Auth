# Authentication API

This repository contains the new version of Authentication API. It is intended to augment the previous [Auth-Api](https://github.com/FlyingCockatoo/Auth-Api).


### CI/CD

[![Build Status](https://dev.azure.com/song88-fci/fci/_apis/build/status/API/Auth%20-%20API?repoName=FlyingCockatoo%2FAuth&branchName=main)](https://dev.azure.com/song88-fci/fci/_build/latest?definitionId=251&repoName=FlyingCockatoo%2FAuth&branchName=main)


### Endpoints

| Environment | Location |                 URL                  | Deployment |
|-------------|----------|--------------------------------------|------------|
| Staging     | HongKong | https://preprod-authapi.song88.com   | ![Status](https://vsrm.dev.azure.com/song88-fci/_apis/public/Release/badge/7de96350-72ac-478e-8f30-2a4ae0c44a60/186/430) |
| Production  | HongKong | https://authapi.song88.com           | ![Status](https://vsrm.dev.azure.com/song88-fci/_apis/public/Release/badge/7de96350-72ac-478e-8f30-2a4ae0c44a60/186/502) |

### Schema

Requires database, see [appsettings.json](Auth.Api/appsettings.json)

### Security

Review the JWT (Json Web Token) security options during deployment.