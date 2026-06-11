# Use the official .NET 8 runtime as base image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Use the official .NET 8 SDK for building
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy everything first and debug what we have
COPY . .

# Debug: Show what files are available
RUN echo "=== All files in build context ===" && \
    find . -type f | head -20 && \
    echo "=== Looking for .csproj files ===" && \
    find . -name "*.csproj" -type f && \
    echo "=== Directory structure ===" && \
    ls -la

# Find the .csproj file and restore
RUN find . -name "*.csproj" -exec dotnet restore {} \;

# Build the project
RUN find . -name "*.csproj" -exec dotnet build {} -c Release -o /app/build \;

FROM build AS publish
RUN find . -name "*.csproj" -exec dotnet publish {} -c Release -o /app/publish /p:UseAppHost=false \;

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

LABEL org.opencontainers.image.created=${BUILDTIME}
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.revision=${REVISION}
LABEL org.opencontainers.image.title="Authly"
LABEL org.opencontainers.image.description="Modern Authentication Server"
LABEL org.opencontainers.image.source="https://git.mjhome.cz/mklouda/authly"
LABEL org.opencontainers.image.url="https://git.mjhome.cz/mklouda/authly"
LABEL org.opencontainers.image.documentation="https://git.mjhome.cz/mklouda/authly/src/branch/master/README.md"
LABEL org.opencontainers.image.vendor="mklouda"
LABEL org.opencontainers.image.licenses="MIT"

# Create data directory for file storage
RUN mkdir -p /app/data

# Debug: Show what was published
RUN echo "=== Published files ===" && ls -la

# Set the entry point using JSON array format
ENTRYPOINT ["dotnet", "Authly.dll"]
