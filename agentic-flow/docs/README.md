# Agentic Flow Documentation

Welcome to Agentic Flow - a next-generation AI orchestration framework that builds upon the foundation of Claude Flow with enhanced provider support, improved architecture, and enterprise-ready features.

## 📚 Documentation Overview

### Getting Started
- **[Quick Start Guide](./quick-start.md)** - Get up and running in 5 minutes
- **[Installation Guide](./installation.md)** - Detailed installation instructions
- **[Migration from Claude Flow](./migration-guide.md)** - Migrate existing Claude Flow projects

### Core Concepts
- **[Architecture Overview](./architecture.md)** - System design and components
- **[API Reference](./api-reference.md)** - Complete API documentation
- **[Provider Integration](./providers/)** - Multi-provider AI support

### Advanced Topics
- **[Workflow Examples](./examples/)** - Real-world workflow patterns
- **[Performance Tuning](./performance.md)** - Optimization guidelines
- **[Security & Compliance](./security.md)** - Enterprise security features

## 🚀 Key Features

### Multi-Provider Support
Agentic Flow supports multiple AI providers out of the box:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude 3)
- Google (Gemini, PaLM)
- Cohere
- Ollama (local models)
- Custom providers via plugin system

### Enhanced Architecture
- **Modular Design**: Clean separation of concerns
- **Plugin System**: Extensible architecture
- **Event-Driven**: Reactive programming model
- **Distributed**: Built for scale

### Enterprise Features
- **Authentication & Authorization**: Role-based access control
- **Audit Logging**: Complete activity tracking
- **High Availability**: Fault-tolerant design
- **Monitoring**: Built-in observability

## 📖 Documentation Index

### Core Documentation
1. [Architecture Overview](./architecture.md)
2. [API Reference](./api-reference.md)
3. [CLI Reference](./cli-reference.md)
4. [Configuration Guide](./configuration.md)

### Provider Guides
- [OpenAI Integration](./providers/openai.md)
- [Anthropic Integration](./providers/anthropic.md)
- [Google AI Integration](./providers/google.md)
- [Cohere Integration](./providers/cohere.md)
- [Ollama Integration](./providers/ollama.md)
- [Custom Provider Development](./providers/custom.md)

### Workflow & Examples
- [Basic Workflows](./examples/basic-workflows.md)
- [Advanced Patterns](./examples/advanced-patterns.md)
- [Multi-Agent Orchestration](./examples/multi-agent.md)
- [RAG Implementation](./examples/rag-implementation.md)

### Migration & Compatibility
- [Migration from Claude Flow](./migration-guide.md)
- [Breaking Changes](./breaking-changes.md)
- [Compatibility Matrix](./compatibility.md)

### Advanced Topics
- [Performance Optimization](./performance.md)
- [Security Best Practices](./security.md)
- [Deployment Guide](./deployment.md)
- [Troubleshooting](./troubleshooting.md)

## 🏃 Quick Start

```bash
# Install Agentic Flow
npm install -g agentic-flow

# Initialize a new project
agentic init my-project

# Configure providers
agentic config set provider.openai.key YOUR_API_KEY

# Run your first workflow
agentic run examples/hello-world.yaml
```

## 🔄 Migrating from Claude Flow

If you're coming from Claude Flow, Agentic Flow maintains backward compatibility while offering new features:

```bash
# Install migration tool
npm install -g agentic-flow-migrate

# Analyze your project
agentic-migrate analyze ./my-claude-flow-project

# Run migration
agentic-migrate run ./my-claude-flow-project
```

See the [Migration Guide](./migration-guide.md) for detailed instructions.

## 📚 Learning Path

### For Beginners
1. Start with the [Quick Start Guide](./quick-start.md)
2. Review [Basic Workflows](./examples/basic-workflows.md)
3. Explore the [CLI Reference](./cli-reference.md)

### For Claude Flow Users
1. Read the [Migration Guide](./migration-guide.md)
2. Check [Breaking Changes](./breaking-changes.md)
3. Review new [Provider Integration](./providers/) options

### For Advanced Users
1. Deep dive into [Architecture](./architecture.md)
2. Study [Advanced Patterns](./examples/advanced-patterns.md)
3. Implement [Custom Providers](./providers/custom.md)

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](../CONTRIBUTING.md) for details.

## 📞 Support

- **Documentation**: You're here!
- **Issues**: [GitHub Issues](https://github.com/agentic-flow/agentic-flow/issues)
- **Discussions**: [GitHub Discussions](https://github.com/agentic-flow/agentic-flow/discussions)
- **Discord**: [Join our community](https://discord.gg/agentic-flow)

## 📄 License

Agentic Flow is licensed under the MIT License. See [LICENSE](../LICENSE) for details.