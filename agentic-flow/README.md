# Agentic Flow

Enterprise-grade agentic workflow orchestration system for Claude Flow.

## 🚀 Quick Start

### Prerequisites

- Node.js 20.x or higher
- npm 9.x or higher
- Docker (optional, for containerized development)
- PostgreSQL (optional, can use Docker)
- Redis (optional, can use Docker)

### Development Setup

1. **Clone and setup the environment:**
   ```bash
   cd agentic-flow
   ./scripts/setup-dev.sh
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start development server:**
   ```bash
   npm run dev
   ```

4. **Run tests:**
   ```bash
   npm test
   npm run test:watch  # Watch mode
   npm run test:e2e    # End-to-end tests
   ```

## 📦 Build & Deployment

### Local Build

```bash
npm run build          # Build TypeScript
npm run docker:build   # Build Docker image
npm run docker:run     # Run Docker container
```

### Docker Compose (Full Stack)

```bash
docker-compose up -d   # Start all services
docker-compose logs -f # Follow logs
docker-compose down    # Stop all services
```

### Kubernetes Deployment

```bash
kubectl apply -f k8s/  # Deploy to Kubernetes
npm run k8s:deploy     # Alternative command
```

## 🔄 CI/CD Pipeline

### GitHub Actions Workflows

- **CI Pipeline** (`.github/workflows/ci.yml`):
  - Lint and type checking
  - Unit, integration, and E2E tests
  - Security scanning
  - Docker image building
  - Automated deployments

- **Release Management** (`.github/workflows/release.yml`):
  - Semantic versioning
  - Automated changelog generation
  - NPM publishing
  - GitHub releases

### Deployment Environments

- **Development**: Auto-deploy on `develop` branch
- **Staging**: Auto-deploy on `release/*` branches  
- **Production**: Auto-deploy on `main` branch (after tests pass)

## 📊 Monitoring & Observability

### Health Checks

- **Health**: `GET /health` - Application health status
- **Readiness**: `GET /ready` - Kubernetes readiness probe

### Metrics & Monitoring

- **Prometheus**: Metrics collection on `/metrics`
- **Grafana**: Dashboards and visualization
- **Jaeger**: Distributed tracing
- **Winston**: Structured logging

### Monitoring Stack (Docker Compose)

```bash
docker-compose up -d

# Access monitoring tools:
# - Grafana: http://localhost:3001 (admin/admin)
# - Prometheus: http://localhost:9090
# - Jaeger: http://localhost:16686
```

## 🛡️ Security

### Security Features

- **Helmet.js**: Security headers
- **CORS**: Cross-origin resource sharing
- **Rate limiting**: API request throttling
- **Input validation**: Request validation with Joi
- **Security scanning**: Snyk and npm audit
- **Container security**: Non-root user, read-only filesystem

### Security Commands

```bash
npm run security:audit  # Run security audit
npm run security:fix    # Fix vulnerabilities
```

## 🧪 Testing

### Test Types

- **Unit Tests**: Fast, isolated component tests
- **Integration Tests**: Component interaction tests
- **E2E Tests**: Full application workflow tests
- **Performance Tests**: Load and performance testing

### Test Commands

```bash
npm test                # Run all tests with coverage
npm run test:unit       # Unit tests only
npm run test:integration # Integration tests only
npm run test:e2e        # End-to-end tests only
npm run test:watch      # Watch mode
npm run test:ci         # CI mode with coverage
```

### Coverage Requirements

- **Branches**: 80%
- **Functions**: 80%
- **Lines**: 80%
- **Statements**: 80%

## 📋 Development Workflow

### Git Hooks (Husky)

- **Pre-commit**: Linting and formatting
- **Pre-push**: Type checking and tests

### Commit Convention

Uses [Conventional Commits](https://www.conventionalcommits.org/):

```bash
feat: add new workflow engine
fix: resolve memory leak in agent pool
docs: update API documentation
chore: update dependencies
```

### Code Quality

```bash
npm run lint            # ESLint checking
npm run lint:fix        # Auto-fix linting issues
npm run format          # Prettier formatting
npm run format:check    # Check formatting
npm run typecheck       # TypeScript checking
```

## 🏗️ Architecture

### Project Structure

```
agentic-flow/
├── src/                    # Source code
│   ├── workflows/          # Workflow orchestration
│   ├── mcp/               # MCP protocol implementation
│   ├── config/            # Configuration management
│   ├── utils/             # Utility functions
│   └── routes/            # API routes
├── tests/                 # Test files
├── k8s/                   # Kubernetes manifests
├── docker/                # Docker configurations
├── scripts/               # Build and deployment scripts
└── config/                # Configuration files
```

### Key Components

- **Workflow Engine**: Orchestrates agentic workflows
- **MCP Integration**: Model Context Protocol support
- **Monitoring**: Comprehensive observability
- **Security**: Enterprise-grade security measures

## 🚀 Production Deployment

### Environment Configuration

Required environment variables for production:

```bash
NODE_ENV=production
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
JWT_SECRET=your-secure-secret
ENCRYPTION_KEY=your-32-char-key
```

### Scaling

- **Horizontal Pod Autoscaler**: Auto-scaling based on CPU/memory
- **Load Balancing**: NGINX with upstream load balancing
- **Redis Cluster**: Distributed caching and queuing
- **Database Replication**: PostgreSQL read replicas

### Performance

- **Docker Multi-stage**: Optimized container images
- **Compression**: Gzip compression for HTTP responses
- **Caching**: Redis-based caching strategy
- **Connection Pooling**: Database connection optimization

## 📚 API Documentation

### Endpoints

- `GET /health` - Health check
- `GET /ready` - Readiness check
- `GET /metrics` - Prometheus metrics
- `POST /api/v1/workflows` - Create workflow
- `GET /api/v1/workflows/:id` - Get workflow status

### API Documentation

Generate API docs:

```bash
npm run docs  # Generate TypeDoc documentation
```

## 🔧 Configuration

### Environment Variables

See `.env.example` for all available configuration options.

### Feature Flags

- `ENABLE_EXPERIMENTAL_FEATURES`: Enable experimental features
- `ENABLE_DEBUG_MODE`: Enable debug logging
- `ENABLE_MAINTENANCE_MODE`: Enable maintenance mode

## 🐛 Troubleshooting

### Common Issues

1. **Port already in use**: Change `PORT` in `.env`
2. **Database connection**: Check `DATABASE_URL` configuration
3. **Redis connection**: Verify `REDIS_URL` setting
4. **Docker issues**: Ensure Docker daemon is running

### Debug Mode

```bash
NODE_ENV=development LOG_LEVEL=debug npm run dev
```

### Health Diagnostics

```bash
curl http://localhost:3000/health
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

### Development Guidelines

- Follow TypeScript best practices
- Write comprehensive tests
- Update documentation
- Use conventional commit messages

## 📄 License

MIT License - see LICENSE file for details.

## 🆘 Support

- **Issues**: GitHub Issues
- **Documentation**: `/docs` directory
- **API Reference**: Generated TypeDoc documentation

---

Built with ❤️ for enterprise-grade agentic workflow orchestration.