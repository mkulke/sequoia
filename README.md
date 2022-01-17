Sequoia PGP
===========

Sequoia is a cool new OpenPGP implementation.  It consists of several
crates, providing both a low-level and a high-level API for dealing
with OpenPGP data.

Low-level API
-------------

The low-level API can be found in the [openpgp](./openpgp) crate.
This crate
aims to provide a complete implementation of OpenPGP as defined by RFC
4880 as well as several extensions (e.g., RFC 6637, which describes
ECC cryptography for OpenPGP, and RFC 4880bis, the draft of the next
OpenPGP standard).  This includes support for unbuffered message
processing.

The [openpgp](./openpgp) crate tries hard to avoid dictating how
OpenPGP should
be used.  This doesn't mean that we don't have opinions about how
OpenPGP should be used in a number of common scenarios (for instance,
message validation).

High-level API
--------------

The high-level API can be found in the [sequoia](.) crate, which
conveniently includes all the other crates.  The high-level API
include a public key store, and network access routines.

Please note that as of this writing the high-level API is very
incomplete.

Command line interface
----------------------

Sequoia includes a simple frontend `sq` (crate [sq](./sq)) that
can be used to experiment with Sequoia and OpenPGP. It is also an
example of how to use various aspects of Sequoia.


Project status
==============

The low-level API is quite feature-complete and can be used encrypt,
decrypt, sign, and verify messages.  It can create, inspect, and
manipulate OpenPGP data on a very low-level.

The high-level API is effectively non-existent, though there is some
functionality related to key servers and key stores.

The foreign function interface provides a C API for some of Sequoia's
low- and high-level interfaces, but it is incomplete.

There is a mostly feature-complete command-line verification tool for
detached messages called ['sqv'].

['sqv']: https://gitlab.com/sequoia-pgp/sequoia-sqv


LICENSE
=======

Sequoia is licensed under the GNU Library General Public License
version 2 or any later version.  See the file
[LICENSE.txt](LICENSE.txt) or visit
https://www.gnu.org/licenses/lgpl-2.0.html for details.

Using Sequoia
=============

If you want to use Sequoia from Rust, you can simply register the
dependency in your `Cargo.toml` file as with any other project.

```toml
sequoia-openpgp = "*"
```

Note that we depend on a number of C libraries, which must be present
along with their development packages. See **Requirements** section
below.

Besides being a Rust crate, we also provide a C API, and bindings to
other languages, see **Bindings**.

Features
--------

Sequoia is currently supported on a variety of platforms.

### Cryptography

By default it uses the Nettle cryptographic library (version 3.4.1 or
up) but it can be used with different cryptographic backends. At the
time of writing, it also supports the native Windows [Cryptographic
API: Next Generation (CNG)].

Various backends can be enabled via Cargo features,
e.g. `crypto-nettle` or `crypto-cng` and exactly one can be enabled at
a time.

Currently, the `crypto-nettle` feature is enabled by default -
regardless of the operating system used. If you choose to enable a
different backend, please make sure to disable the default first.

### Example

To use the Windows CNG backend, use:

```toml
# Cargo.toml
[dependencies]
sequoia-openpgp = { version = "*", default-features = false, features = ["crypto-cng"] }
```

```bash
# When building locally
$ cargo build --manifest-path=openpgp/Cargo.toml --no-default-features --features crypto-cng
```

### Note

If you are developing a crate that depends on Sequoia, please ensure
the users can opt into different backends. This is done by:

- disabling default features for `sequoia-openpgp`
- providing top-level features for your crate that correspond to
  `crypto-*` ones in `sequoia-openpgp`
- (Optionally) Select one by default yourself

Like so:
```toml
# Cargo.toml
[dependencies]
sequoia-openpgp = { version = "*", default-features = false }
[features]
# Pick a Sequoia backend enabled by default
default = ["seqouia-openpgp/crypto-nettle"]
# .. but allow others to select a different backend, as well
crypto-cng = ["sequoia-openpgp/crypto-cng"]
crypto-nettle = ["sequoia-openpgp/crypto-nettle"]
```

Once Cargo target-specific default features are [implemented], it will
be possible to automatically select a backend depending on the
operating system used.

[implemented]: https://github.com/rust-lang/cargo/issues/1197#issuecomment-590385530

### Compression

By default, Sequoia supports compression via `flate2` and `bzip2`
crates, enabled by `compression-deflate` and `compression-bzip2` Cargo
features respectively (also available via `compression` shorthand
feature).

[Cryptographic API: Next Generation (CNG)]: https://docs.microsoft.com/windows/win32/seccng/cng-portal

Building Sequoia
================

Using Cargo
-----------

To build all Sequoia components, simply execute `cargo build
[--release] --all`.  Individual components may be built independently,
e.g. to build `sq`, run `cargo build [--release] -p sequoia-sq`, or
build `sequoia-openpgp-ffi` to build a shared object with the C API.

Using Docker
------------

The command line tool `sq` can also be built using Docker:

```shell
$ docker build -t sq .
$ docker run --rm -i sq --help
```

For example retrieving a certificate and inspecting its contents:

```shell
$ docker run --rm -i sq keyserver get 653909A2F0E37C106F5FAF546C8857E0D8E8F074 > cert.asc
$ docker run --rm -i sq packet dump < cert.asc
```

A current build of the docker image is available from the gitlab registry.
Rename it to `sq` locally so that it matches the above commands and for convenience.

```shell
$ docker pull registry.gitlab.com/sequoia-pgp/sequoia:latest
$ docker tag registry.gitlab.com/sequoia-pgp/sequoia:latest sq
$ docker run --rm -i sq --help
```

## Requirements

To build Sequoia, you need at least Rust 1.56 and a few libraries,
notably the Nettle cryptographic library version 3.4.1 or up.  Please
see below for OS-specific commands to install the needed libraries:

### Debian

```shell
$ sudo apt install git rustc cargo clang libclang-dev make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev
```

Notes:

  - You need at least `rustc` version 1.56.  This is the version included in
    Debian 12 (bookworm) at the time of writing.  You can use [rustup] if your
    distribution only includes an older Rust version.
  - You need at least Nettle 3.4.1.  Both the versions in Debian 10 (Buster)
    and Debian 11 (Bullseye) are fine.

[rustup]: https://rustup.rs/

### Arch Linux

```shell
$ sudo pacman -S git cargo clang make pkg-config nettle openssl capnproto sqlite3 --needed
```

### Fedora

```shell
$ sudo dnf install git rustc cargo clang make pkg-config nettle-devel openssl-devel capnproto sqlite-devel
```

### NixOS

Development environment for use with `nix-shell` or `direnv`:
<details>
  <summary>
    `shell.nix`
  </summary>

```nix
let
  oxalica_overlay = import (builtins.fetchTarball
    "https://github.com/oxalica/rust-overlay/archive/master.tar.gz");
  nixpkgs = import <nixpkgs> { overlays = [ oxalica_overlay ]; };
  rust_channel = nixpkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain;
in with nixpkgs;
pkgs.mkShell {
  buildInputs = [
    nettle
    openssl
    sqlite
  ];

  nativeBuildInputs = [
    (rust_channel.override{
        extensions = [ "rust-src" "rust-std" ];
    })

    llvmPackages.clang
    pkgconfig
    capnproto

    # tools
    codespell
  ];

  RUST_BACKTRACE = 1;

  # compilation of -sys packages requires manually setting LIBCLANG_PATH
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
}
```

</details>


### macOS

#### MacPorts

```shell
$ sudo port install cargo rust capnproto nettle pkgconfig coreutils
```

#### Brew

```shell
$ brew install rust capnp nettle
```

If building the transitive dependency `nettle-sys` reports missing `libclang.dylib` file make sure that `DYLD_LIBRARY_PATH` is set correctly:

```shell
export DYLD_LIBRARY_PATH=/Library/Developer/CommandLineTools/usr/lib/
```

### Windows

Please make sure to preserve line-endings when cloning the Sequoia
repository.  The relevant git option is `core.autocrlf` which must be
set to `false`.

#### MSYS2

You can install the needed libraries with the following command:

```shell
$ pacboy -S base-devel toolchain:x clang:x bzip2:x nettle:x sqlite3:x capnproto:x
```

Due to Gitlab's Windows Shared Runners being somewhat slow, we only
run them automatically for MRs, which contain `windows` in the branch
name. Please name your branch accordingly when contributing a patch
which might affect Windows.

#### MSVC

To build Sequoia, you need to have [`capnp`] tool installed.

Only the native Windows Cryptographic API (CNG) is supported, see
**Using Sequoia (Cryptography)** section above.

When building, make sure to disable default features (to disable
Nettle) and enable the CNG via `crypto-cng` Cargo feature:

```bash
$ cargo build --no-default-features --features crypto-cng,compression # Only change crypto backend
```

[`capnp`]: https://capnproto.org/install.html


Getting help
============

Sequoia's documentation is hosted here: https://docs.sequoia-pgp.org/

The [guide](./guide) is hosted here: https://sequoia-pgp.org/guide/

You can join our mailing list by sending a mail to
devel-subscribe@lists.sequoia-pgp.org.

You can talk to us using IRC on freenode in #sequoia.

Reporting bugs
==============

Please report bug and feature requests to [our bugtracker].  Please
report security vulnerabilities to [security@sequoia-pgp.org],
preferably encrypted using OpenPGP.  The certificate for this address
can be found on our web site, via WKD, and [on the keyserver].


  [our bugtracker]: https://gitlab.com/sequoia-pgp/sequoia/issues
  [security@sequoia-pgp.org]: mailto:security@sequoia-pgp.org
  [on the keyserver]: https://keys.openpgp.org/search?q=security%40sequoia-pgp.org
