# Coding conventions

We strive to make Sequoia's APIs and code as consistent and predictable as
possible, to ease maintenance and make Sequoia easy and safe to use.

## Rust

We do not use automated tools to format our source code. For some of us, the
source is an expression of art, and must not be mutilated by some algorithm.
Furthermore, "fixing" the formatting obscures the version control history,
making it less useful when trying to understand how the code evolved over time.

Nevertheless, we do have some rules that we try to stick to:

- maximum line length is 79 characters
- line breaks before operators
- expressive, yet short, variable names unless the scope is small.
  If choosing acronyms or short names that are not obvious by the context,
  add a comment in the definition to explain what they are.
- No whitespaces at the end of the line.
- No comma without a whitespace after.
- Function signatures that do not fit in one line [clearer traits]:

  ```rust
  fn some_function<T, U>(t: T, u: U) -> i32
      where T: Display + Clone,
            U: Clone + Debug
  {
  ```

Each of us also have some personal preferences, that are good to know to choose
to follow them or not.

- No space before colon.
- [Rust Style Guide].

It is important to note that these are not strict rules. Sometimes, adhering to
the rules has severe disadvantages, and sometimes it may not even be possible.

As a general rule, please try to make the code look nice. Remember, the code is
written for humans to understand. Writing good looking code, such that it is
easy to read and understand is more important than strict adherence to a set of
rules.

## Rust Documentation

We follow [RFC 1574].

[RFC 1574]: https://github.com/rust-lang/rfcs/blob/master/text/1574-more-api-documentation-conventions.md#appendix-a-full-conventions-text

And:

- No link in the short module description.
- Quotes need to be indented.
- Reflow text to use all available space.
  - Unless lines separated by dot.
  - Unless quoted from other text, for instance RFC (which is 72 characters
    per line).
- Whenever we doubt or ask about something, it probably needs more
  documentation or comments.

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

[clearer traits]: https://doc.rust-lang.org/stable/book/ch10-02-traits.html#clearer-trait-bounds-with-where-clauses
[Rust Style Guide]: https://github.com/rust-dev-tools/fmt-rfcs/blob/master/guide/guide.md
