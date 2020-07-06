# NEAR-pool

Rust ZeroPool implementation for NEAR blockchain.

## Components

- [ ] client application
- [x] smart contract
- [x] circuit and cryptography

### Client application

Building in progress now...

### Smart contract

You may check [pool-contract](https://github.com/zeropoolnetwork/NEAR-pool/tree/master/pool-contract#README) for more details.
Currently it is working with zeropool forks of [nearcore](https://github.com/zeropoolnetwork/nearcore) and [near-sdk-rs](https://github.com/zeropoolnetwork/near-sdk-rs)


### Circuit and cryptography

Done. Check [pool-crypto](https://github.com/zeropoolnetwork/NEAR-pool/tree/master/pool-crypto#README). Also, you may build `pool-prover` to provide zkSNARK trusted setup and prove some transfers.

```
USAGE:
    pool-prover <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    generate-test-data    Generate test object
    help                  Prints this message or the help of the given subcommand(s)
    prove                 Generate a SNARK proof
    setup                 Generate trusted setup parameters
    verify                Verify a SNARK proof

```


