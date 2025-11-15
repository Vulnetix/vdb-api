# Testing Quick Start Guide

## 🚀 Get Testing in 5 Minutes

### 1. Install Test Tools (One-Time Setup)

```bash
# Install test dependencies
just test-install

# Or manually
npm install -g httpyac openapi-to-postmanv2
```

### 2. Configure Your Credentials

Edit `tests/test.config.http`:

```http
@baseUrl = http://localhost:8778
@orgId = YOUR_ORG_UUID_HERE
@orgSecret = YOUR_ORG_SECRET_HERE
@token = YOUR_JWT_TOKEN_HERE
```

### 3. Start Development Server

```bash
just dev
```

### 4. Run Tests

**Option A: Automated Test Suite**
```bash
just test                # Run all tests
just test-verbose        # Verbose output
just test-prod          # Test production
```

**Option B: VS Code REST Client**
```bash
# Install extension
code --install-extension humao.rest-client

# Open any test file
code tests/v1/info/cve-info.http

# Click "Send Request" or press Ctrl+Alt+R
```

**Option C: Postman Extension**
```bash
# Install extension
code --install-extension Postman.postman-for-vscode

# Import OAS: Ctrl+Shift+P → "Postman: Import API Specification"
# URL: http://localhost:8778/v1/spec
```

## 📋 Available Test Commands

```bash
just test              # Run all integration tests
just test-verbose      # Run with verbose output
just test-prod         # Test against production
just test-generate     # Generate tests from OAS
just test-clean        # Clean test artifacts
```

## 🗂️ Test Structure

```
tests/
├── v1/auth/token.http          # Authentication
├── v1/info/cve-info.http       # CVE metadata
├── v1/vuln/vulnerability.http  # Vulnerability data
├── v1/exploits/exploit-intel.http  # Exploit intel
└── oas/openapi.http           # OpenAPI spec
```

## 🎯 Common Test Scenarios

### Test OpenAPI Spec
```http
GET http://localhost:8778/v1/spec
```

### Get CVE Information
```http
GET http://localhost:8778/v1/info/CVE-2024-1234
Authorization: Bearer YOUR_TOKEN
```

### Get Vulnerability Data
```http
GET http://localhost:8778/v1/vuln/CVE-2024-1234
Authorization: Bearer YOUR_TOKEN
```

### Get Exploit Intelligence
```http
GET http://localhost:8778/v1/exploits/CVE-2024-1234
Authorization: Bearer YOUR_TOKEN
```

## 🔧 Troubleshooting

**Tests fail with 401 Unauthorized**
- Update JWT token in `tests/test.config.http`
- Tokens expire in 15 minutes

**httpyac not found**
```bash
npm install -g httpyac
```

**Server not responding**
```bash
# Ensure dev server is running
just dev

# Check correct port (8778)
curl http://localhost:8778/v1/spec
```

## 📚 More Information

- Full testing guide: [`tests/README.md`](tests/README.md)
- API documentation: [`README.md`](README.md)
- OpenAPI spec: http://localhost:8778/v1/swagger

## 🎓 VS Code Extensions

### REST Client (Recommended)
```bash
code --install-extension humao.rest-client
```
- Open `.http` files
- Click "Send Request"
- Keyboard: `Ctrl+Alt+R` (Win/Linux) or `Cmd+Alt+R` (Mac)

### Postman
```bash
code --install-extension Postman.postman-for-vscode
```
- Import OAS automatically
- Full Postman experience in VS Code
- Collection runner built-in

### Thunder Client (Alternative)
```bash
code --install-extension rangav.vscode-thunder-client
```
- Lightweight HTTP client
- Collections and environments
- Similar to Postman

## 🤖 CI/CD Integration

Add to `.github/workflows/test.yml`:

```yaml
- name: Run API Tests
  run: |
    npm install -g httpyac
    ./tests/scripts/run-tests.sh
```

## 🎉 You're Ready!

Start testing your API endpoints with confidence. Happy testing! 🚀
