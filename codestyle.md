# Code Style Guide

Short reference for consistent code. See `assignment-and-research.txt` for full project plan.

## Principles

- **Clarity over cleverness** — straightforward solutions
- **Single responsibility** — one function, one job
- **Self-documenting names** — `userAuthToken`, `calculateTotalPrice()`, not `tkn`, `calc()`
- **Minimal dependencies** — add libraries only when necessary

## Comments

- **DO** comment: complex algorithms, business decisions, edge cases, security considerations
- **DON'T** comment: obvious loops, variable assignments, self-explanatory code
- Style: lowercase first letter, concise, explain *why* not *what*

```python
# using binary search because dataset can be 10M+ records
result = binary_search(data, target)
```

## Structure

- Group related code together
- Separate concerns (business logic, UI, data access)
- Return early to reduce nesting
- Use named constants instead of magic numbers

## Git

- Commit messages: brief bullet — what changed — why
- Never push unless explicitly requested
