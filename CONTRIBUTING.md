# Contributing to Bellbook

Thanks for your interest. Bellbook is a verification kernel, so the bar for
changes is correctness first: the verifier's behavior is the product.

## Ground rules

- **SPEC.md and the code must move together.** A change to record semantics,
  verification rules, hashing, or the storage format needs a matching SPEC.md
  edit in the same pull request.
- **Every behavior change needs a test.** Verifier rules additionally need a
  rejection test (which `ReasonCode`, from which input).
- **No `unwrap()`/`expect()`/`panic!` in library code** (tests are fine), no
  `unsafe`, no new dependencies without prior discussion in an issue.
- Hash-affecting changes (canonical form, schema names, ref ordering) break
  every existing log. They need a schema version bump and a CHANGELOG entry
  calling out the break loudly.

## Workflow

1. Open an issue describing the problem before large changes.
2. Make sure the full local gate passes:

   ```
   cargo fmt --check
   cargo clippy --locked --all-targets --all-features -- -D warnings
   cargo test --locked
   cargo test --no-default-features --lib --locked
   RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
   ```

3. Keep commits scoped; explain *why* in the message body.

## Security

Suspected soundness breaks in verification, hashing, or the commit protocol
go through [SECURITY.md](SECURITY.md), not the public issue tracker.

## License

By contributing you agree that your contributions are dual-licensed under
MIT OR Apache-2.0, per the repository license.
