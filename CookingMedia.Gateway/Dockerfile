FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["CookingMedia.Gateway/CookingMedia.Gateway.csproj", "CookingMedia.Gateway/"]
RUN dotnet restore "CookingMedia.Gateway/CookingMedia.Gateway.csproj"
COPY . .
WORKDIR "/src/CookingMedia.Gateway"
RUN dotnet build "CookingMedia.Gateway.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "CookingMedia.Gateway.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "CookingMedia.Gateway.dll"]
