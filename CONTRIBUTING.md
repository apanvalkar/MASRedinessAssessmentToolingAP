# Contributing to MAS9 Source Readiness

Thank you for considering contributing.

## Contribution Principles
- Keep checks **read-only**
- Prefer **static analysis** over runtime probing
- Every check must include:
  - Purpose
  - MAS9-specific rationale
  - Clear output definition

## Adding a New Check
1. Create a new check class/module
2. Define:
   - Check ID
   - Risk category
   - RAG impact
3. Add unit or sample validation
4. Update documentation if user-visible

## Code Style
- Java: follow standard formatting
- Scripts: avoid environment assumptions
- No hard-coded credentials

## Pull Requests
- One feature per PR
- Include sample output if format changes
