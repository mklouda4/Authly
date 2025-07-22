# Use the official .NET 8 runtime as base image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Use the official .NET 8 SDK for building
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY Authly.csproj .
RUN dotnet restore Authly.csproj
COPY . .
RUN dotnet build Authly.csproj -c Release -o /app/build

FROM build AS publish
RUN dotnet publish Authly.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
# Create data directory for file storage
RUN mkdir -p /app/data
# Set the entry point using JSON array format
ENTRYPOINT ["dotnet", "Authly.dll"]