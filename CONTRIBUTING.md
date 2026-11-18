# Contributing to OpenABE

## Before opening a pull request

Before opening a pull request:

1. Create a dedicated branch from `master`.
2. Keep the change focused on a single issue or goal.
3. Avoid unrelated formatting-only edits.
4. Run `clang-format` on modified C/C++ files.
5. Build and test locally before submitting the PR.

Example:

```bash
. ./env
make
make test
make -C examples test
git diff --check
```

To format a C/C++ file:

```bash
clang-format -i --style=file path/to/file.cpp
```

The style is defined in [.clang-format](.clang-format) and enforced by CI with
**clang-format 18.1.8**. Other versions may produce slightly different output, so
use the same one locally:

```bash
pipx install clang-format==18.1.8   # or: pip install clang-format==18.1.8
```

Generated files (bison/flex output) are listed in [.clang-format-ignore](.clang-format-ignore)
and are never reformatted.

## Pull request requirements

The pull request should clearly describe:

- the problem being fixed or the feature being introduced;
- the approach taken;
- the tests that were run;
- any known limitations or caveats;
- the impact on compatibility and security.

Any change related to cryptography, key handling, serialization, or protocol logic should include a detailed technical explanation to support review.

## CI checks

The CI pipeline automatically verifies:

- C/C++ formatting;
- build success;
- unit tests;
- example tests;
- Python bindings;
- CLI utilities.

A pull request should not be considered ready until the automated checks pass successfully.