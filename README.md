# sign-tx-frost
testing code to sign tx with taproot input and frost

To use there is a need to fix paths in the `Cargo.toml`

```
frost-core = { version = "1.0.0-rc.0", features = ["serde"], path = "../frost.copy/frost-core" }
...
frost-secp256k1-tr = { version = "1.0.0-rc.0", features = ["serde"], path = "../frost.copy/frost-secp256k1-tr"  }
```

- `generate` command outputs to stdout and this can be saved in testdata.json
- `address` command show address on generated VerifyinKey in the testdata.json
- `sendtoaddress` allow sign and get hex of output transaction with arguments in the form:

```
sendtoaddress tb1pqkgsz274gjnkdxp7v9rpzwqtqtjacjp5t2mz2vaqu2r6qln8qsesve6uez 1000 02000000000101bf2d2d426...
```

Where last part is a hex of transaction which makes output on generated address.
