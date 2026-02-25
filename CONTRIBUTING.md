# Contributing to OpenDirectory

Thank you for your interest in contributing to OpenDirectory! We welcome contributions from the community and are pleased you've chosen to be a part of our open source project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Security](#security)
- [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

### Prerequisites

Before contributing, ensure you have the following installed:

- **Node.js**: Version 18 or higher
- **Docker & Docker Compose**: For containerized development
- **Git**: For version control
- **kubectl**: For Kubernetes development (optional)

### Fork and Clone the Repository

1. Fork the OpenDirectory repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/yourusername/OpenDirectory.git
   cd OpenDirectory
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/opendirectory/OpenDirectory.git
   ```

## Development Setup

### Local Environment

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your local configuration
   ```

3. **Start the development environment:**
   ```bash
   # Start infrastructure services
   docker-compose up -d postgres redis mongodb rabbitmq lldap
   
   # Start platform services
   cd services/platform
   docker-compose up -d
   
   # Start core services
   cd ../core
   ./start-services.sh
   ```

4. **Access the application:**
   - Web Interface: http://localhost:3000
   - API Gateway: http://localhost:8080
   - API Documentation: http://localhost:8080/docs

### Kubernetes Development

For Kubernetes development:

```bash
# Deploy to local cluster
kubectl apply -f infrastructure/kubernetes/

# Check deployment status
kubectl get pods -n opendirectory

# Port forward for local access
kubectl port-forward svc/api-gateway 8080:80 -n opendirectory
```

## How to Contribute

### Areas for Contribution

We welcome contributions in the following areas:

1. **Bug Fixes**: Fix existing issues and improve stability
2. **Feature Development**: Implement new features from our roadmap
3. **Platform Support**: Add support for additional platforms
4. **Mobile Agents**: Enhance iOS/Android management capabilities
5. **Security Enhancements**: Improve zero-trust and security features
6. **Documentation**: Improve docs, tutorials, and examples
7. **Testing**: Add tests and improve test coverage
8. **Performance**: Optimize performance and scalability

### Finding Issues to Work On

- Check the [Issues](https://github.com/opendirectory/OpenDirectory/issues) tab
- Look for issues labeled `good first issue` for beginners
- Issues labeled `help wanted` are particularly welcome
- Check the [Project Board](https://github.com/opendirectory/OpenDirectory/projects) for planned features

### Creating Issues

When creating new issues, please:

1. **Check existing issues** to avoid duplicates
2. **Use issue templates** when available
3. **Provide clear descriptions** with steps to reproduce
4. **Include environment details** (OS, browser, versions)
5. **Add relevant labels** to categorize the issue

## Pull Request Process

### Before Submitting

1. **Create a new branch** for your feature/fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our coding standards

3. **Test your changes:**
   ```bash
   npm run test
   npm run test:e2e
   npm run lint
   ```

4. **Update documentation** if needed

5. **Commit your changes** with descriptive messages:
   ```bash
   git commit -m "feat: add user authentication middleware
   
   - Implement JWT token validation
   - Add role-based access control
   - Update API documentation
   
   Closes #123"
   ```

### Submitting the Pull Request

1. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a pull request** on GitHub with:
   - Clear title and description
   - Reference to related issues
   - Screenshots/demos for UI changes
   - Test evidence
   - Breaking change notes (if any)

3. **Respond to feedback** and make requested changes

### Pull Request Requirements

- [ ] Code follows our coding standards
- [ ] Tests are added for new functionality
- [ ] Documentation is updated
- [ ] All CI checks pass
- [ ] No merge conflicts
- [ ] Commit messages follow conventional commit format

## Coding Standards

### JavaScript/TypeScript

We follow these conventions:

- **ESLint**: Use the provided ESLint configuration
- **Prettier**: Code formatting is handled automatically
- **Naming**: Use camelCase for variables, PascalCase for classes
- **Functions**: Prefer arrow functions for inline usage
- **Async/Await**: Use async/await over Promises.then()

### Code Structure

```javascript
// Good
const getUserById = async (id) => {
  try {
    const user = await userService.findById(id);
    return user;
  } catch (error) {
    logger.error('Failed to get user', { id, error });
    throw new UserNotFoundError(id);
  }
};

// Service organization
class UserService {
  constructor(repository, logger) {
    this.repository = repository;
    this.logger = logger;
  }

  async create(userData) {
    // Implementation
  }
}
```

### Error Handling

- Use custom error classes for different error types
- Log errors with context information
- Return appropriate HTTP status codes
- Include error codes for client handling

### Security Guidelines

- Never commit secrets or credentials
- Validate and sanitize all inputs
- Use parameterized queries for database operations
- Implement proper authentication and authorization
- Follow OWASP security guidelines

## Testing Guidelines

### Test Types

1. **Unit Tests**: Test individual functions and classes
2. **Integration Tests**: Test service interactions
3. **End-to-End Tests**: Test complete user workflows
4. **Security Tests**: Test authentication and authorization

### Writing Tests

```javascript
// Unit test example
describe('UserService', () => {
  let userService;
  let mockRepository;

  beforeEach(() => {
    mockRepository = {
      findById: jest.fn(),
      create: jest.fn()
    };
    userService = new UserService(mockRepository);
  });

  describe('getUserById', () => {
    it('should return user when found', async () => {
      const userId = '123';
      const expectedUser = { id: userId, name: 'John Doe' };
      mockRepository.findById.mockResolvedValue(expectedUser);

      const result = await userService.getUserById(userId);

      expect(result).toEqual(expectedUser);
      expect(mockRepository.findById).toHaveBeenCalledWith(userId);
    });
  });
});
```

### Test Coverage

- Maintain minimum 80% code coverage
- Focus on critical paths and edge cases
- Test error conditions and failure scenarios
- Include performance tests for critical operations

## Documentation

### API Documentation

- Use OpenAPI/Swagger specifications
- Include request/response examples
- Document error responses
- Provide authentication details

### Code Documentation

- Document public APIs with JSDoc
- Include usage examples
- Explain complex business logic
- Update README files for service changes

### Architecture Documentation

- Update architecture diagrams for structural changes
- Document design decisions in ADRs (Architecture Decision Records)
- Maintain deployment documentation
- Update security documentation

## Security

### Reporting Security Vulnerabilities

Please do not create public GitHub issues for security vulnerabilities. Instead:

1. Email security issues to: security@opendirectory.org
2. Provide detailed information about the vulnerability
3. Allow time for the team to address the issue before public disclosure

### Security Best Practices

- Follow secure coding guidelines
- Use dependency scanning tools
- Implement security headers
- Regular security audits
- Principle of least privilege

## Community

### Communication Channels

- **GitHub Discussions**: For questions and general discussion
- **Slack/Discord**: Real-time chat (link in README)
- **Monthly Meetings**: Community calls (calendar link)
- **Email**: For private matters

### Getting Help

- Check existing documentation
- Search previous issues
- Ask in community channels
- Create detailed issues for bugs

### Recognition

Contributors are recognized through:

- Contributor list in README
- Release notes mentions
- Community highlights
- Contributor badges

## Development Workflow

### Branch Naming

- `feature/description` - New features
- `bugfix/description` - Bug fixes
- `hotfix/description` - Critical fixes
- `docs/description` - Documentation updates

### Commit Messages

Follow conventional commit format:

```
type(scope): brief description

Detailed explanation of the change
including motivation and context.

Closes #issue-number
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### Release Process

1. Features merged to `main` branch
2. Automated testing and security scans
3. Release candidate testing
4. Semantic versioning
5. Release notes generation
6. Docker image publishing

## Questions?

If you have questions not covered here:

1. Check the [FAQ](docs/FAQ.md)
2. Search existing [issues](https://github.com/opendirectory/OpenDirectory/issues)
3. Join our community discussions
4. Create a new issue with the `question` label

Thank you for contributing to OpenDirectory!