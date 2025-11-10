# Contributing to ChronoGuard

Thank you for your interest in contributing to ChronoGuard! This document provides guidelines for contributing to the project.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior through GitHub Issues or Security Advisories.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear description** of the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Python version, Docker version)
- **Logs and error messages** (if applicable)
- **Screenshots** (if relevant)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide detailed description** of the proposed functionality
- **Explain why this enhancement would be useful** to ChronoGuard users
- **List any alternative solutions** you've considered

### Pull Requests

1. **Fork the repository** and create your branch from `master`
2. **Follow the development workflow** (see below)
3. **Ensure all tests pass** and coverage remains at 95%+
4. **Update documentation** as needed
5. **Write clear commit messages** following conventional commits
6. **Reference related issues** in your PR description

---

## Development Workflow

### Prerequisites

- **Python 3.11+** (required)
- **Poetry** (dependency management)
- **Docker** and Docker Compose (for services)
- **Git** (version control)

### Initial Setup

```bash
# 1. Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/ChronoGuard.git
cd ChronoGuard

# 2. Install dependencies
cd backend
poetry install

# 3. Start development services
cd ..
docker compose -f deployments/docker/docker-compose.dev.yml up -d

# 4. Run tests to verify setup
make test
```

### Development Process

#### 1. Create a Feature Branch

```bash
git checkout -b feat/your-feature-name
# or
git checkout -b fix/bug-description
```

**Branch Naming Convention:**
- `feat/feature-name` - New features
- `fix/bug-description` - Bug fixes
- `docs/what-changed` - Documentation updates
- `refactor/component-name` - Code refactoring
- `test/test-description` - Test additions

#### 2. Make Your Changes

Follow the [Coding Guidelines](CODING_GUIDELINES.md):

- **Professional naming** - No marketing terms like "optimized", "enhanced"
- **Type hints required** - All functions must have complete type annotations
- **Docstrings required** - Google-style docstrings for all public functions
- **DRY principle** - No duplicate code
- **Clean Architecture** - Respect layer boundaries

#### 3. Run Quality Checks

After every source file change:

```bash
# Format code
poetry run black backend/src/ backend/tests/
poetry run isort backend/src/ backend/tests/

# Lint code
poetry run ruff check backend/src/ backend/tests/

# Type check
poetry run mypy backend/src/ backend/tests/
```

Or use the Makefile:

```bash
make format  # Auto-format
make lint    # Run linters
make type-check  # Run mypy
```

#### 4. Write Tests

**Test coverage must be 95%+ (strict requirement)**

```bash
# Run tests with coverage
make test

# Generate coverage report
make test-coverage

# View coverage HTML report
open htmlcov/index.html
```

**Test Requirements:**
- Unit tests for all new functions/classes
- Integration tests for new API endpoints
- Edge cases and error paths must be tested
- Mock external dependencies (OPA, databases)

#### 5. Commit Changes

Follow conventional commit format:

```bash
# Good commit messages
git commit -m "feat: add weekend restriction support to policy engine"
git commit -m "fix: correct hash chain validation for first entry"
git commit -m "docs: update API documentation for new endpoints"
git commit -m "test: add integration tests for time restrictions"

# Commit types
# feat:     New feature
# fix:      Bug fix
# docs:     Documentation changes
# test:     Test additions/changes
# refactor: Code refactoring
# chore:    Build process or tooling changes
# perf:     Performance improvements
```

#### 6. Push and Create PR

```bash
git push origin feat/your-feature-name
```

Then create a Pull Request on GitHub with:
- **Clear title** describing the change
- **Description** explaining what and why
- **Tests** section showing test coverage
- **Breaking changes** noted (if any)
- **Related issues** referenced with #issue-number

---

## Pull Request Guidelines

### Before Submitting

- [ ] All tests pass locally (`make test`)
- [ ] Coverage is at 95%+ (`make test-coverage`)
- [ ] No mypy errors (`make type-check`)
- [ ] No ruff/black errors (`make lint`)
- [ ] Documentation updated (if API changed)
- [ ] CHANGELOG.md updated (for significant changes)
- [ ] Commit messages follow conventional commits

### PR Description Template

```markdown
## Description
Brief description of what this PR does.

## Motivation
Why is this change needed? What problem does it solve?

## Changes
- List of specific changes made
- File-by-file breakdown if complex

## Testing
- How was this tested?
- What test cases were added?
- Coverage impact: XX% → YY%

## Breaking Changes
- List any breaking changes
- Migration guide (if applicable)

## Related Issues
Closes #123
Related to #456
```

### Review Process

1. **Automated Checks**: GitHub Actions runs tests, linting, type checking
2. **Code Review**: At least one maintainer approval required
3. **Coverage Check**: Must maintain or improve 95%+ coverage
4. **Security Review**: Security-sensitive changes get extra scrutiny
5. **Merge**: Squash and merge (maintainers will handle)

---

## Code Quality Standards

### Required Checks

All code must pass these checks before merging:

```bash
# Run all quality checks
make quality

# Or individually:
poetry run ruff check backend/src/
poetry run black --check backend/src/
poetry run isort --check-only backend/src/
poetry run mypy backend/src/
```

### Architecture Guidelines

**Follow Clean Architecture:**
```
presentation/ ──> application/ ──> domain/ <── infrastructure/
```

**Dependency Rules:**
- Domain layer NEVER imports infrastructure
- Application layer can import domain
- Presentation layer imports application
- Infrastructure implements domain interfaces

**CQRS Pattern:**
- Commands for mutations (create, update, delete)
- Queries for reads (get, list, search)
- Separate concerns clearly

### Test Standards

```python
# Good test example
@pytest.mark.asyncio
async def test_create_agent_validates_certificate_expiration():
    """Test that expired certificates are rejected during agent creation.

    Given: An agent creation request with expired certificate
    When: CreateAgentCommand is executed
    Then: BusinessRuleViolationError is raised with expiration message
    """
    # Given
    expired_cert = create_expired_certificate()
    request = CreateAgentRequest(name="test", certificate=expired_cert)

    # When/Then
    with pytest.raises(BusinessRuleViolationError) as exc:
        await command.execute(request, tenant_id=UUID4())

    assert "expired" in str(exc.value).lower()
```

**Test Requirements:**
- Descriptive test names (test_what_when_then)
- Comprehensive docstrings
- Given/When/Then structure
- Cover success and error paths
- Use proper fixtures

---

## Development Tools

### Recommended VS Code Extensions

```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.vscode-pylance",
    "ms-python.black-formatter",
    "charliermarsh.ruff",
    "matangover.mypy",
    "tsandall.opa"
  ]
}
```

### Pre-commit Hooks (Optional)

```bash
# Install pre-commit
poetry add --group dev pre-commit

# Set up hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

### Debugging

```bash
# Run single test with debugging
PYTHONPATH=backend/src poetry run pytest backend/tests/unit/test_agent_domain.py::test_specific -v -s

# Run with debugger
PYTHONPATH=backend/src poetry run pytest backend/tests/unit/test_agent_domain.py::test_specific --pdb

# Run integration tests
docker compose -f backend/tests/integration/docker-compose.test.yml up -d
make test-integration
```

---

## Documentation

### API Documentation

API changes require OpenAPI spec updates:
- Endpoint descriptions
- Request/response examples
- Error codes and meanings

### Architecture Documentation

Significant architectural changes require updates to:
- `docs/architecture/architecture.md`
- `docs/architecture/architecture-diagrams.md`
- Architecture decision records (if ADRs adopted)

### User Guides

User-facing features need documentation:
- How-to guides in `docs/guides/`
- Examples in `examples/`
- README.md updates

---

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **Major** (X.0.0): Breaking changes, incompatible API changes
- **Minor** (0.X.0): New features, backwards-compatible
- **Patch** (0.0.X): Bug fixes, backwards-compatible

### Release Checklist

- [ ] All tests pass with 95%+ coverage
- [ ] CHANGELOG.md updated with changes
- [ ] Version bumped in pyproject.toml
- [ ] Documentation updated
- [ ] Security review completed (if applicable)
- [ ] Docker images built and tested
- [ ] Release notes prepared
- [ ] GitHub release created with tag

---

## Getting Help

### Resources

- **Documentation**: [docs/](docs/)
- **Architecture**: [docs/architecture/](docs/architecture/)
- **Coding Guidelines**: [CODING_GUIDELINES.md](CODING_GUIDELINES.md)
- **API Docs**: http://localhost:8000/docs (when running)

### Communication

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community discussion
- **Pull Requests**: Code contributions and reviews

### Common Questions

**Q: How do I run just one test?**
```bash
PYTHONPATH=backend/src poetry run pytest backend/tests/unit/test_file.py::test_name -v
```

**Q: How do I update dependencies?**
```bash
poetry update
poetry lock
# Test thoroughly before committing
```

**Q: My tests are failing with import errors?**
```bash
# Ensure PYTHONPATH is set
export PYTHONPATH=backend/src
# or use Makefile commands which set it automatically
make test
```

**Q: How do I add a new API endpoint?**
1. Add route handler in `presentation/api/routes/`
2. Add command/query in `application/`
3. Add domain logic (if needed) in `domain/`
4. Add unit tests achieving 95%+ coverage
5. Add integration test
6. Update OpenAPI docs

---

## First-Time Contributors

Welcome! Here's how to get started:

1. **Find an issue** labeled `good-first-issue` or `help-wanted`
2. **Comment** on the issue to express interest
3. **Wait for assignment** to avoid duplicate work
4. **Ask questions** - we're happy to help!
5. **Start small** - first PR should be simple to learn the process
6. **Read** CODING_GUIDELINES.md thoroughly

### Good First Issues

Look for issues tagged:
- `good-first-issue` - Suitable for newcomers
- `documentation` - Documentation improvements
- `help-wanted` - Community help requested
- `test` - Test additions

---

## Recognition

Contributors will be recognized in:
- GitHub Contributors page
- Release notes (for significant contributions)
- CHANGELOG.md (for feature contributions)

---

## Questions?

If you have questions not covered here:
- Check existing [GitHub Discussions](https://github.com/j-raghavan/ChronoGuard/discussions)
- Create a new discussion
- Ask in your Pull Request

Thank you for contributing to ChronoGuard!

---

**Last Updated**: 2025-11-08
