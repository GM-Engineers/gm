# Docker Deployment Guide for GM CA Server

This directory contains Docker configuration for deploying the GM CA Server with PostgreSQL.

## Quick Start

### 1. Start PostgreSQL Only (for development)

```bash
# Start PostgreSQL
docker compose up postgres -d

# Check logs
docker compose logs postgres

# Stop PostgreSQL
docker compose down
```

### 2. Start Full Stack (PostgreSQL + GM CA Server)

```bash
# Build and start all services
docker compose up -d

# Check logs
docker compose logs -f

# Stop all services
docker compose down
```

### 3. Rebuild after Code Changes

```bash
# Rebuild the GM CA Server image
docker compose build gm-ca-server

# Restart the service
docker compose up -d gm-ca-server
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| postgres | 5432 | PostgreSQL database |
| gm-ca-server | 50051 | GM CA gRPC server |

## Environment Variables

### PostgreSQL

| Variable | Default | Description |
|----------|---------|-------------|
| POSTGRES_USER | postgres | Database user |
| POSTGRES_PASSWORD | **required** | Database password (no default) |
| POSTGRES_DB | gm_ca | Database name |

### GM CA Server

| Variable | Default | Description |
|----------|---------|-------------|
| DATABASE_URL | **required** | Database connection URL (e.g., `postgres://user:password@postgres:5432/gm_ca`) |
| CA_AUTH_TOKEN | **required** | Bearer token for gRPC authentication |
| CA_KEY_PATH | /app/data/ca_key.pem | CA private key path |
| CA_SUBJECT_CN | GM CA | CA subject common name |
| RUST_LOG | info | Log level |

## Persistent Storage

| Volume | Purpose |
|--------|---------|
| postgres_data | PostgreSQL data directory |
| ca_data | CA private key storage |

## Health Checks

Both services include health checks:

```bash
# Check service status
docker compose ps

# PostgreSQL health
docker exec gm-ca-postgres pg_isready -U postgres

# GM CA Server health (requires grpcurl)
grpcurl -plaintext localhost:50051 grpc.health.v1.Health/Check
```

## Development Usage

### Connect to PostgreSQL

```bash
# Using docker exec
docker exec -it gm-ca-postgres psql -U postgres -d gm_ca

# Using local psql client
psql -h localhost -U postgres -d gm_ca
```

### Run GM CA Server Locally (with Docker PostgreSQL)

```bash
# Start only PostgreSQL
docker compose up postgres -d

# Run GM CA Server locally
cd gm
export DATABASE_URL="postgres://user:password@localhost:5432/gm_ca"
export CA_AUTH_TOKEN="$(openssl rand -hex 32)"
cargo run --release -p gm-ca-server
```

### Run Tests

```bash
# Start PostgreSQL for testing
docker compose up postgres -d

# Wait for PostgreSQL to be ready
sleep 5

# Run tests
cd gm
export DATABASE_URL="postgres://user:password@localhost:5432/gm_ca"
cargo test -p gm-ca
```

## Data Persistence

### Backup Database

```bash
# Create backup
docker exec gm-ca-postgres pg_dump -U postgres gm_ca > backup.sql

# Or use docker compose
docker compose exec postgres pg_dump -U postgres gm_ca > backup.sql
```

### Restore Database

```bash
# Restore from backup
cat backup.sql | docker exec -i gm-ca-postgres psql -U postgres gm_ca
```

### Backup CA Key

```bash
# Copy CA key from container
docker cp gm-ca-server:/app/data/ca_key.pem ./ca_key_backup.pem
```

## Troubleshooting

### PostgreSQL Connection Issues

```bash
# Check if PostgreSQL is running
docker compose ps postgres

# Check PostgreSQL logs
docker compose logs postgres

# Test connection
docker exec gm-ca-postgres psql -U postgres -c "SELECT 1"
```

### GM CA Server Issues

```bash
# Check server logs
docker compose logs gm-ca-server

# Check if port is available
lsof -i :50051

# Test gRPC health
grpcurl -plaintext localhost:50051 grpc.health.v1.Health/Check
```

### Reset Everything

```bash
# Stop and remove all containers, networks, and volumes
docker compose down -v

# Rebuild from scratch
docker compose up --build -d
```

## Security Considerations

1. **Change default passwords** in production:
   ```yaml
   environment:
     POSTGRES_PASSWORD: your-secure-password
   ```

2. **Use secrets** for sensitive data:
   ```yaml
   secrets:
     ca_key:
       file: ./secrets/ca_key.pem
   ```

3. **Network isolation**: Remove port exposure for PostgreSQL in production

4. **TLS for gRPC**: Configure TLS for gRPC endpoints in production
