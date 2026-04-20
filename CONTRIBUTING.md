# Contributing to ATF (Agent-Tool-Firewall)

Thank you for your interest in contributing to ATF!

**Important Note**:
This project is currently in an **early development stage**. It is a functional proof-of-concept that demonstrates a viable approach to protecting local LLM agents from indirect prompt injection, but it is **not yet production-ready**. The codebase, documentation, testing, and security practices still need significant refinement and ongoing maintenance.

Because of this, ATF would benefit greatly from a dedicated maintainer who has the time and interest to steward the project — including rule maintenance, security reviews, CI/CD improvements, and general polishing.

If you are interested in becoming a co-maintainer or taking a more active role in the project's long-term development, please feel free to open an Issue or Discussion.

## Project Philosophy

- Keep ATF as a **single static Go binary** with **zero external runtime dependencies**.
- Prefer pure-Go solutions.
- Use layered defense: sanitization + Coraza WAF with anomaly scoring.
- Keep SecLang rules external and human-maintainable.

## Getting Started

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/durg78/agent-tool-firewall.git
   cd agent-tool-firewall
   ```

2. Build the project:
   ```bash
   go build -trimpath -ldflags="-s -w" -o atf-proxy ./cmd/atf-proxy
   ```

3. Run tests:
   ```bash
   ./run_tests.sh
   ```

### Prerequisites
- Go 1.22+
- Git

## Development Workflow

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes.

3. Ensure it builds cleanly:
   ```bash
   go build -trimpath -ldflags="-s -w" -o atf-proxy ./cmd/atf-proxy
   ```

4. Test thoroughly with the malicious test suite.

5. Commit with clear messages.

6. Open a Pull Request.

## Areas of Contribution

### High Priority
- New or improved SecLang detection rules
- Enhancements to the pure-Go sanitizer
- Handling edge cases and new attack vectors
- **Project security & CI/CD** (GitHub Actions, automated testing, dependency scanning, etc.)
- General code quality, testing, and documentation improvements

### Other Welcome Contributions
- Docker / deployment support
- Additional test cases
- Configuration and UX enhancements

## Project Security & CI/CD

Contributions that improve ATF’s security posture and automation are highly valued:
- GitHub Actions workflows (build, test, lint, release)
- Security scanning (dependabot, CodeQL, osv-scanner)
- Fuzz testing
- Container / supply chain security

## Testing

Run the full test suite:

```bash
# Start the test server (in one terminal)
cd test/malicious
python3 -m http.server 8000

# In another terminal
./run_tests.sh
```

All malicious test cases should return **403 Forbidden**.

## Submitting Pull Requests

Please:
- Keep changes focused
- Clearly describe the problem and solution
- Add or update tests when relevant
- Update documentation for any behavioral changes

### Rule Contributions
When adding/modifying rules:
- Include the attack example
- Explain scoring impact
- Test against both malicious and benign content

## Questions or Ideas?

Feel free to open a GitHub Issue or Discussion.

---

**Thank you for helping make local LLM agents safer!**

---
