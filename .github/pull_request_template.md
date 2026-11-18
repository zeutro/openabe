## Summary

Briefly describe what this pull request changes and why.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Performance improvement
- [ ] Security or cryptography-related change
- [ ] Documentation update
- [ ] Refactoring
- [ ] Code formatting
- [ ] Other

## Scope of the change

Indicate which parts of the project are affected:

- [ ] `src/`
- [ ] `cli/`
- [ ] `examples/`
- [ ] `bindings/`
- [ ] `deps/`
- [ ] Documentation
- [ ] GitHub Actions / build system

## Validation performed

List the commands you ran locally:

```bash
. ./env
make
make test
```

If applicable:

```bash
make -C examples test
```

## Formatting

- [ ] I applied `clang-format` to the modified C/C++ files.
- [ ] I ran `git diff --check`.
- [ ] The formatting check passes locally.

## Compatibility

Describe any impact on compatibility with Linux, Windows/MSYS2, macOS, or Python.

## Security

If this change affects cryptographic primitives, key handling, serialization, or protocols:

- describe the security impact;
- state any assumptions or constraints;
- explain which tests were performed.

## Reviewer notes

Add any context that may help reviewers, such as limitations, trade-offs, design decisions, or areas that need extra attention.