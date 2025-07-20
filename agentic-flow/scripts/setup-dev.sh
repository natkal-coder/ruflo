#!/bin/bash
set -e

echo "🚀 Setting up Agentic Flow Development Environment"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Node.js version
    if ! command -v node &> /dev/null; then
        print_error "Node.js is not installed. Please install Node.js 20.x or higher."
        exit 1
    fi
    
    node_version=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$node_version" -lt 20 ]; then
        print_error "Node.js version must be 20.x or higher. Current version: $(node -v)"
        exit 1
    fi
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed."
        exit 1
    fi
    
    # Check Docker (optional)
    if ! command -v docker &> /dev/null; then
        print_warning "Docker is not installed. Some features may not work."
    fi
    
    # Check Redis (optional)
    if ! command -v redis-cli &> /dev/null; then
        print_warning "Redis CLI is not installed. Will use Docker Redis if available."
    fi
    
    print_success "Prerequisites check completed"
}

# Install dependencies
install_dependencies() {
    print_status "Installing dependencies..."
    npm ci
    print_success "Dependencies installed"
}

# Setup environment
setup_environment() {
    print_status "Setting up environment configuration..."
    
    if [ ! -f .env ]; then
        cp .env.example .env
        print_success "Environment file created from example"
        print_warning "Please update .env file with your actual configuration"
    else
        print_warning ".env file already exists, skipping creation"
    fi
}

# Setup Git hooks
setup_git_hooks() {
    print_status "Setting up Git hooks..."
    if [ -d .git ]; then
        npx husky install
        print_success "Git hooks installed"
    else
        print_warning "Not a Git repository, skipping Git hooks setup"
    fi
}

# Setup databases
setup_databases() {
    print_status "Setting up databases..."
    
    if command -v docker &> /dev/null; then
        print_status "Starting database services with Docker..."
        docker-compose up -d postgres redis
        
        # Wait for databases to be ready
        print_status "Waiting for databases to be ready..."
        sleep 10
        
        # Run database migrations (if any)
        if [ -f "scripts/migrate.sh" ]; then
            ./scripts/migrate.sh
        fi
        
        print_success "Databases are ready"
    else
        print_warning "Docker not available. Please ensure PostgreSQL and Redis are running manually."
    fi
}

# Run tests
run_tests() {
    print_status "Running tests to verify setup..."
    npm run test -- --passWithNoTests
    print_success "Tests completed"
}

# Build project
build_project() {
    print_status "Building project..."
    npm run build
    print_success "Project built successfully"
}

# Main setup function
main() {
    echo "=========================================="
    echo "  Agentic Flow Development Setup"
    echo "=========================================="
    
    check_prerequisites
    install_dependencies
    setup_environment
    setup_git_hooks
    setup_databases
    build_project
    run_tests
    
    echo ""
    echo "=========================================="
    print_success "Development environment setup complete!"
    echo "=========================================="
    echo ""
    echo "Next steps:"
    echo "1. Update your .env file with actual configuration"
    echo "2. Run 'npm run dev' to start development server"
    echo "3. Run 'npm run test:watch' for continuous testing"
    echo "4. Check README.md for additional information"
    echo ""
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --skip-tests   Skip running tests during setup"
        echo "  --skip-docker  Skip Docker-based database setup"
        echo ""
        exit 0
        ;;
    --skip-tests)
        run_tests() { print_warning "Skipping tests as requested"; }
        ;;
    --skip-docker)
        setup_databases() { print_warning "Skipping Docker database setup as requested"; }
        ;;
esac

# Run main setup
main