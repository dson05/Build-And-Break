# Secure ATM/Bank Prototype

This repository contains a CMSC 414 build-it/break-it project: a small ATM and bank system written in C, plus the router used to carry messages between them. The bank and ATM communicate over UDP, but all ATM-to-bank traffic is protected with AES-256-GCM and a simple nonce-based replay defense.

The project centers on four executables:

- `init`: generates the shared secret used by the ATM and bank
- `bank`: maintains user accounts in memory and creates `.card` files
- `atm`: authenticates users and performs `balance` and `withdraw`
- `router`: forwards UDP datagrams between the ATM and bank

## Security model

- `init` creates `<name>.bank` and `<name>.atm`, each containing the same 32-byte key encoded as hex.
- The bank stores each user's PIN, balance, and a random 32-byte card secret in memory.
- Each `<user>.card` file contains only that user's card secret, not the PIN.
- ATM requests and bank responses are encrypted and authenticated with AES-256-GCM.
- Each ATM request carries a fresh random nonce. The bank keeps a ring of recently seen nonces and drops replays.
- Requests are tagged with `R` and responses with `A` so the ATM and bank can reject reflections or misdirected packets.

This gives the system two-factor authentication for ATM sessions:

1. Something the user has: `<user>.card`
2. Something the user knows: a 4-digit PIN

## Build

Requirements:

- `make`
- `gcc` or `clang`
- OpenSSL `libcrypto`

Build everything with:

```sh
make
```

Notes:

- On macOS, the `Makefile` looks for Homebrew OpenSSL via `brew --prefix openssl`.
- On Linux, it links against the system `libcrypto`.

## Quick start

Build the project, initialize shared state, then run the router, bank, and ATM in separate terminals.

```sh
make
./bin/init /tmp/demo
```

Terminal 1:

```sh
./bin/router
```

Terminal 2:

```sh
./bin/bank /tmp/demo.bank
```

Terminal 3:

```sh
./bin/atm /tmp/demo.atm
```

Example session:

At the bank:

```text
BANK: create-user Alice 1234 100
Created user Alice
```

At the ATM:

```text
ATM: begin-session Alice
PIN? 1234
Authorized

ATM (Alice):  balance
$100

ATM (Alice):  withdraw 25
$25 dispensed

ATM (Alice):  end-session
User logged out
```

## Commands

`bank` supports:

- `create-user <user-name> <pin> <balance>`
- `deposit <user-name> <amt>`
- `balance <user-name>`

`atm` supports:

- `begin-session <user-name>`
- `balance`
- `withdraw <amt>`
- `end-session`

The exact assignment-facing behavior is documented in [bank.md](bank.md), [atm.md](atm.md), and [init.md](init.md).

## Repository layout

- `init.c`: creates `.bank` and `.atm` initialization files
- `bank/`: bank process and command handling
- `atm/`: ATM process and session logic
- `router/`: UDP forwarding layer
- `util/crypto.c`: AES-GCM helpers and hex encoding utilities
- [`design.md`](design.md): protocol and threat-model write-up
- `public2.py`: lightweight public test harness
- `break-it/6825f15e/`: archived break-it submission materials and attack notes

## Limitations

- Account state exists only in memory while the bank process is running.
- The design assumes a single ATM talking to a single bank instance.
- There is no online PIN rate limiting.
- A hostile router can still deny service by dropping packets.

## Verification

Useful commands while working on the project:

```sh
make
python3 public2.py .
```

`public2.py` requires the Python `pexpect` package.
