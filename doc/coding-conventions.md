# Coding conventions

We strive to make Sequoia's APIs and code as consistent and
predictable as possible, to ease maintenance and make Sequoia easy and
safe to use.

## Rust

We do not use automated tools to format our source code.  The source
is an expression of art, and must not be mutilated by some algorithm.
Furthermore, "fixing" the formatting obscures the version control
history, making it less useful when trying to understand how the code
evolved over time.

Nevertheless, we do have some rules that we try to stick to:

  - maximum line length is 80 characters
  - line breaks before operators
  - expressive, yet short, variable names unless the scope is small

It is important to note that these are not strict rules.  Sometimes,
adhering to the rules has severe disadvantages, and sometimes it may
not even be possible.

As a general rule, please try to make the code look nice.  Remember,
the code is written for humans to understand.  Writing good looking
code, such that it is easy to read and understand is more important
than strict adherence to a set of rules.

## Documentation

We follow [RFC 1574].

[RFC 1574]: https://github.com/rust-lang/rfcs/blob/master/text/1574-more-api-documentation-conventions.md#appendix-a-full-conventions-text

## Identifiers and documentation

This is a list of OpenPGP-specific terminology and how we represent it
in the code and documentation.

| Terminology | method names | parameter names | in the C API | documentation |
|-------------|--------------|-----------------|--------------|---------------|
| Algorithm   | algo         | algo            | algo         | Algorithm     |
| Fingerprint | fingerprint  | fp              | fingerprint  | Fingerprint   |
| Key Flags   | keyflags     | flags           | keyflags     | Key Flags     |
| Key ID      | keyid        | keyid, id       | keyid        | Key ID        |
| User ID     | userid       | userid, uid     | userid       | User ID       |

