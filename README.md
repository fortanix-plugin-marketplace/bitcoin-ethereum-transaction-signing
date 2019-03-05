# Hierarchical Deterministic (HD) wallets Plugin
This plugin sign transaction from ethererum private key
## Initial setup
import BIP32 master key in SDKMS as secrete object in raw byte format

**Example BIP32 Master Key:** xprv9s21ZrQH143K2yLSxbXemfny4nZroqhpiXEQ1MYx8vo2k7HRXypsWesNr7GkWTuU9CeaW7QeR38NjjaSfZBAAZVkVEpXwEkxLLXP2q1iFUd

## Plugin input and output for transaction signing for Ethereum
Plugin takes master key-id, derivation path and message hash (SHA3) as json input and return signature as response

**Example: Input**
```
{
	"masterKeyId": "fbd70d51-9719-4da8-8f0f-1d304b78df44",
	"path": "m/2",
	"msgHash" :"9b36423a63ea806822ba2ce8c8bdd2ac78a8606daf4d230efc932290312150b8"
}
```
**Example: Output**
```
{
	"signature": "B28D2E235FC6B8BA899E528FA6325F54B12881D88DAE7A1752C9019B89A9FDCB4975E2C3BF587FC5D38AE965C45B7B38D31A0012E9FC131FBEFFAEC9C420D2F51C"
}
```

# License

This project is primarily distributed under the terms of the Apache License, Version 2.0 (the "License"), see [LICENSE](./LICENSE) for details.
