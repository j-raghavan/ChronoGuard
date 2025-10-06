# Pull Request

## Description

<!-- Provide a clear and concise description of what this PR does -->

### Type of Change

<!-- Mark the relevant option with an [x] -->

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📝 Documentation update
- [ ] 🎨 Code refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] 🔒 Security fix
- [ ] 🧪 Test improvements
- [ ] 🔧 Configuration/Infrastructure changes

## Motivation and Context

<!-- Why is this change required? What problem does it solve? -->
<!-- Link to any related issues here using #issue-number -->

Resolves #

## Changes Made

<!-- List the specific changes made in this PR -->

-
-
-

## Testing

### Test Coverage

- [ ] Tests added/updated for new functionality
- [ ] All existing tests pass
- [ ] Code coverage maintained at ≥95%
- [ ] Test coverage report: **___%**

### Test Types

<!-- Mark all that apply -->

- [ ] Unit tests
- [ ] Integration tests
- [ ] End-to-end tests
- [ ] Performance tests

### Test Commands Run

```bash
# Commands used to verify this PR
make test            # Run all tests with coverage
make test-fast       # Quick test validation
make lint            # Code quality checks
make type-check      # Type checking
```

### Test Results

<!-- Paste test output summary here -->

```
✅ XXX tests passing
❌ 0 failures
Coverage: XX.XX%
```

## Code Quality Checklist

### Pre-Commit Checks

- [ ] `make lint` passes (ruff + black)
- [ ] `make format` applied (code formatted)
- [ ] `make type-check` passes (mypy)
- [ ] `make security` passes (bandit)
- [ ] `make test` passes with ≥95% coverage

### Code Standards

- [ ] Follows domain-driven design principles
- [ ] Proper error handling and validation
- [ ] Security best practices applied
- [ ] Timezone-aware datetime handling (UTC)
- [ ] Immutable value objects where appropriate
- [ ] Async/await patterns used correctly
- [ ] Type annotations present and accurate
- [ ] Docstrings added for public methods
- [ ] No security vulnerabilities introduced

### Architecture Standards

- [ ] Domain logic in domain layer
- [ ] Infrastructure separated from domain
- [ ] Service methods are stateless
- [ ] Repository pattern used for persistence
- [ ] Dependency injection used appropriately
- [ ] Feature flags considered for new functionality

## Documentation

- [ ] Code is self-documenting with clear naming
- [ ] Complex logic has explanatory comments
- [ ] Public APIs have comprehensive docstrings
- [ ] README updated (if applicable)
- [ ] TESTING.md updated (if test changes)
- [ ] Architecture diagrams updated (if applicable)

## Security Considerations

- [ ] No hardcoded secrets or credentials
- [ ] Input validation on all user-provided data
- [ ] SQL injection prevention (parameterized queries)
- [ ] XSS prevention applied
- [ ] CSRF protection considered
- [ ] Authentication/authorization checked
- [ ] Rate limiting considered
- [ ] Audit logging added for sensitive operations
- [ ] Certificate validation for mTLS
- [ ] Timezone-aware datetime handling

## Performance Considerations

- [ ] Database queries optimized (indexes, N+1 queries)
- [ ] Async operations used where beneficial
- [ ] Caching strategy considered
- [ ] Memory usage optimized
- [ ] No blocking operations in async code

## Breaking Changes

<!-- If this PR introduces breaking changes, describe them here -->
<!-- Include migration guide for users if applicable -->

**Breaking Changes:** None / Yes (describe below)

## Deployment Notes

<!-- Any special deployment considerations? -->

- [ ] Database migrations required
- [ ] Environment variables added/changed
- [ ] Configuration updates needed
- [ ] Requires service restart
- [ ] Dependencies updated

### New Environment Variables

<!-- List any new environment variables -->

```bash
# Example:
# CHRONOGUARD_FEATURE_NEW_FEATURE=true
```

## Rollback Plan

<!-- How can this change be rolled back if needed? -->

## Screenshots/Logs

<!-- If applicable, add screenshots or log outputs to help explain the changes -->

## Checklist Before Merge

- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] Branch is up to date with target branch
- [ ] No merge conflicts
- [ ] CI/CD pipeline passing
- [ ] Code reviewed by at least one team member
- [ ] All review comments addressed
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if applicable)

## Additional Notes

<!-- Any additional information that reviewers should know -->

---

## For Reviewers

### Review Focus Areas

<!-- Highlight specific areas that need careful review -->

- [ ] Domain logic correctness
- [ ] Security implications
- [ ] Performance impact
- [ ] Test coverage adequacy
- [ ] Error handling completeness
- [ ] API design

### Verification Steps

1. Checkout this branch: `git checkout <branch-name>`
2. Install dependencies: `poetry install`
3. Run tests: `make test`
4. Run linting: `make lint`
5. Review code changes
6. Test functionality manually (if applicable)

---

**Generated with Claude Code** 🤖

Co-Authored-By: Claude <noreply@anthropic.com>
