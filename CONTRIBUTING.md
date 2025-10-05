# Contributing to ShieldGents

Thank you for your interest in contributing to ShieldGents! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs or suggest features
- Search existing issues to avoid duplicates
- Provide detailed information including:
  - Steps to reproduce
  - Expected vs actual behavior
  - Environment details (OS, Python version, etc.)

### Submitting Changes

1. **Fork the repository**
   ```bash
   git clone https://github.com/ApexAILabs/shieldgents.git
   cd shieldgents
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Set up development environment**
   ```bash
   uv sync --all-extras
   ```

4. **Make your changes**
   - Write clear, documented code
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation as needed

5. **Run tests and linting**
   ```bash
   # Run tests
   uv run pytest

   # Type checking
   uv run mypy src/

   # Format code
   uv run black src/ tests/

   # Lint
   uv run ruff check src/ tests/
   ```

6. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new security feature"
   ```

7. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## Development Guidelines

### Code Style

- Follow PEP 8 style guide
- Use Black for formatting (line length: 100)
- Use type hints for all functions
- Write docstrings for all public APIs

### Testing

- Write unit tests for all new code
- Maintain test coverage above 80%
- Include integration tests for new features
- Test edge cases and error conditions

### Documentation

- Update README.md for user-facing changes
- Add docstrings with examples
- Update API documentation
- Include inline comments for complex logic

### Commit Messages

Follow conventional commits format:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test changes
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

## Areas for Contribution

We welcome contributions in these areas:

### Security Features
- New attack pattern detection
- Additional sandboxing capabilities
- Enhanced monitoring and alerting

### Integrations
- Support for more AI frameworks
- Cloud provider integrations
- Observability tool integrations

### Testing
- Additional attack vectors
- Fuzzing improvements
- Performance benchmarks

### Documentation
- Usage examples
- Integration guides
- Best practices documentation

## Review Process

1. All PRs require review from maintainers
2. CI checks must pass
3. Code coverage should not decrease
4. Documentation must be updated

## Questions?

Feel free to open an issue for questions or join our community discussions.

Thank you for contributing to ShieldGents! 🛡️
