# SecDash v2.0

Modern security dashboard for running and aggregating security scans with enterprise-grade architecture.

## 📁 Project Structure

```
SecDash/
├── backend/                 # FastAPI backend application
│   ├── api/v1/             # API endpoints (v1)
│   ├── middleware/         # Custom middleware
│   ├── workers/            # Celery workers
│   └── alembic/           # Database migrations
├── frontend/               # React frontend application
│   └── src/               # Source code
├── config/                 # Configuration files
├── docs/                   # Documentation
├── scripts/                # Setup and utility scripts
│   └── tests/             # Test scripts
└── tools/                  # Security tools Docker configs
```

## 🏗️ Architecture

SecDash v2.0 features a completely redesigned architecture based on modern cloud-native principles:

### Backend & API Layer
- **FastAPI 1.x** with async SQLAlchemy 2.0 & Pydantic v3
- **OpenAPI 3.1** auto-documentation with JWT authentication
- **JSON Merge-Patch** for partial updates
- **Structured logging** with OpenTelemetry traces

### Persistence
- **PostgreSQL 17** as the primary relational database
- **TimescaleDB community extension** for scan telemetry hypertables
- **Alembic** for schema versioning and migrations
- **Redis 7** for caching and session storage

### Job Processing & Real-time
- **Celery 6** workers running in Kubernetes Jobs
- **Redis 7** as message broker and pub/sub for WebSocket pushes
- **Background scan processing** with progress tracking
- **Real-time dashboard updates** via WebSockets

### Authentication & Authorization
- **Self-hosted Keycloak 26.3** (OpenID Connect)
- **Short-lived JWT tokens** with RS256 signing
- **RBAC rules** enforced with Keycloak Authorization Services
- **Multi-tenancy** support for organizations

### Secrets & Configuration
- **HashiCorp Vault OSS** for dynamic scanner credentials
- **PKI certificate management** for internal services
- **Environment-specific configuration** with Pydantic Settings v2

### Security Scanning Toolset
- **Containerized scanners**: Nmap 7.95, OWASP ZAP 4.x, Nuclei 3.x
- **OpenVAS/GVM 23** for vulnerability assessment
- **Metasploit 7 RPC** for exploitation testing
- **Tshark 4** for network analysis
- **Common findings schema** with vulnerability deduplication

### Data Processing & Enrichment
- **CVE/JSON feeds** from NVD with automated updates
- **EPSS scores** for exploit prediction
- **CVSS v4 calculator** for accurate risk scoring
- **Deduplication** keyed on asset-hash + vulnerability-id

### Observability & Error Tracking
- **OpenTelemetry Collector** → self-hosted **Jaeger** for traces/metrics
- **Sentry 24** for exception dashboards and error tracking
- **Structured logging** with correlation IDs
- **Health checks** and service monitoring

### Reporting & Exports
- **Pandoc-rendered PDF/HTML** executive reports
- **CSV/JSON raw dumps** for data analysis
- **Outbound Splunk HEC** and **Elastic ECS** pipeline integrations
- **Customizable report templates**

### Deployment
- **Multi-stage Docker images** with security best practices
- **GitHub Actions CI/CD** with automated testing
- **Helm-managed Kubernetes 1.34** releases
- **/healthz + /readyz** probes for container orchestration
- **WAL-G S3 backups** for data persistence

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose v2.x
- 8GB+ RAM recommended
- Available ports: 3000, 5432, 6379, 8000, 8080, 16686

### 1. Clone and Setup
```bash
git clone <repository-url>
cd SecDash
cp backend/.env.example backend/.env
```

### 2. Start Infrastructure
```bash
# Start all services
docker-compose up -d

# Check service health
docker-compose ps
```

### 3. Initialize Database
```bash
# Run database migrations
docker-compose exec backend alembic upgrade head

# Seed initial data (optional)
docker-compose exec backend python scripts/seed_data.py
```

### 4. Access Services
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000/docs
- **Keycloak Admin**: http://localhost:8080 (admin/admin)
- **Jaeger Tracing**: http://localhost:16686
- **Flower (Celery)**: http://localhost:5555 (admin/admin)

## 🔧 Configuration

### Environment Variables

SecDash uses nested environment variables with double underscores for configuration:

```bash
# Database
DATABASE__URL=postgresql+asyncpg://user:pass@host:port/db
DATABASE__ECHO=false

# Redis
REDIS__BROKER_URL=redis://localhost:6379/1
REDIS__RESULT_BACKEND=redis://localhost:6379/2

# Security
SECURITY__KEYCLOAK_SERVER_URL=http://localhost:8080
SECURITY__KEYCLOAK_REALM=secdash
SECURITY__JWT_ALGORITHM=RS256

# Observability
OBSERVABILITY__JAEGER_ENDPOINT=http://localhost:14268/api/traces
OBSERVABILITY__SENTRY_DSN=your-sentry-dsn
```

### Scanner Configuration

Configure security tools in the settings:

```python
SCANNERS__MAX_CONCURRENT_SCANS=5
SCANNERS__SCAN_TIMEOUT=3600
SCANNERS__NMAP_IMAGE=instrumentisto/nmap:7.95
SCANNERS__ZAP_IMAGE=ghcr.io/zaproxy/zaproxy:2.14.0
SCANNERS__NUCLEI_IMAGE=projectdiscovery/nuclei:v3.1.4
```

## 📊 API Documentation

### OpenAPI Specification
The API is fully documented with OpenAPI 3.1:
- **Interactive docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

### Key Endpoints

#### Assets Management
```http
GET    /api/v1/assets              # List assets with filtering
POST   /api/v1/assets              # Create new asset
GET    /api/v1/assets/{id}         # Get asset details
PATCH  /api/v1/assets/{id}         # Update asset (JSON Merge Patch)
DELETE /api/v1/assets/{id}         # Delete asset
```

#### Scan Operations
```http
GET    /api/v1/scans               # List scans with filters
POST   /api/v1/scans               # Start new scan
GET    /api/v1/scans/{id}          # Get scan details
GET    /api/v1/scans/{id}/status   # Get real-time scan status
POST   /api/v1/scans/{id}/cancel   # Cancel running scan
```

#### Vulnerability Management
```http
GET    /api/v1/vulnerabilities     # List vulnerabilities
GET    /api/v1/vulnerabilities/{id} # Get vulnerability details
PATCH  /api/v1/vulnerabilities/{id} # Update status/notes
```

## 🔒 Security

### Authentication Flow
1. **Frontend** redirects to Keycloak for authentication
2. **Keycloak** issues JWT token with user claims
3. **Backend** validates JWT signature and claims
4. **Authorization** enforced via Keycloak RBAC policies

### Vulnerability Deduplication
SecDash uses SHA-256 hashing for vulnerability deduplication:
```
dedup_hash = sha256(f"{asset_id}:{vuln_id}:{host}:{port}")
```

### Container Security
- **Non-root users** in all containers
- **Read-only file systems** where possible
- **Resource limits** and security contexts
- **Network segmentation** with Docker networks

## 📈 Monitoring & Observability

### Health Checks
- **/health/live**: Liveness probe (200 = service running)
- **/health/ready**: Readiness probe (checks dependencies)
- **/health/health**: Detailed health with metrics

### Distributed Tracing
- **OpenTelemetry** instrumentation for FastAPI and SQLAlchemy
- **Jaeger** for trace collection and visualization
- **Correlation IDs** for request tracking

### Error Tracking
- **Sentry** integration for exception monitoring
- **Structured logging** with JSON format
- **Custom error handlers** with user-friendly messages

## 🏗️ Development

### Local Development Setup
```bash
# Backend development
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# Start services
docker-compose up postgres redis -d

# Run backend
export DATABASE__URL=postgresql+asyncpg://secdash:secdash@localhost:5432/secdash
python main.py

# Frontend development
cd frontend
npm install
npm start
```

### Database Migrations
```bash
# Create new migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

### Adding New Scanners
1. Create transformer in `backend/transformers.py`
2. Add scanner logic in `backend/workers/scan_worker.py`
3. Update Docker images in configuration
4. Add scan profiles in database

## 🚀 Deployment

### Production Deployment
```bash
# Build production images
docker-compose -f docker-compose.prod.yml build

# Deploy with Helm
helm upgrade --install secdash ./helm/secdash \
  --set image.tag=v2.0.0 \
  --set postgresql.enabled=true \
  --set redis.enabled=true
```

### Kubernetes Resources
- **StatefulSets** for PostgreSQL and Redis
- **Deployments** for FastAPI backend and React frontend
- **Jobs** for Celery workers
- **Services** and **Ingress** for networking
- **ConfigMaps** and **Secrets** for configuration

## 📚 Documentation

### Architecture Diagrams
- [System Architecture](docs/architecture.md)
- [Database Schema](docs/database.md)
- [API Design](docs/api.md)
- [Security Model](docs/security.md)

### API Reference
- [Assets API](docs/api/assets.md)
- [Scans API](docs/api/scans.md)
- [Vulnerabilities API](docs/api/vulnerabilities.md)

## 🤝 Contributing

Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Wiki](../../wiki)
- **Issues**: [GitHub Issues](../../issues)
- **Discussions**: [GitHub Discussions](../../discussions)
- **Security**: [Security Policy](SECURITY.md)
