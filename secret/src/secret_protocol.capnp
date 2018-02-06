@0xf4bd406fa822c9db;

interface Store {
  open @0 (fingerprint: Text) -> (result: Result(Key));
  import @1 (key: Data) -> (result: Result(Key));
  iter @2 () -> (result: Result(KeyIter));

  interface Key {
    tpk @0() -> (result: Result(Data));
    unlock @1 (passphrase: Text) -> (result: Result(Unit));
    lock @2 () -> (result: Result(Unit));
    decrypt @3 (sk: Data) -> (result: Result(Data));
    sign @4 (subkeyId: UInt64, hashAlgo: UInt8, digest: Data) -> (result: Result(Data));
  }

  interface KeyIter {
    next @0 () -> (result: Result(Item));

    struct Item {
      fingerprint @0 :Text;
      key @1 :Key;
    }
  }

  # Unit struct.  Useful with Result.
  struct Unit {}

  enum Error {
    notFound @0;
    keyExists @1;
    malformedKey @2;
    malformedFingerprint @3;
    storeLocked @4;
    keyLocked @5;
    badPassphrase @6;
  }

  struct Result(T) {
    union {
      ok @0 :T;
      err @1 :Error;
    }
  }
}
