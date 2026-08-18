# Build-It Design Document

## Overview

This system implements a prototype ATM and bank that communicate over UDP through a router on localhost. The router is not trusted. We assume an attacker controlling the router can inspect, modify, drop, duplicate, and forge packets, but cannot read the `.bank` or `.atm` files or the memory of the ATM or bank processes.

The main security goal is : an attacker should not be able to withdraw money unless they have both:

- the user's ATM card  
- the user's PIN  

To enforce that, the system uses:

- a shared 32-byte master secret between ATM and bank  
- a unique 32-byte random card secret per user  
- HMAC-SHA256 authentication  
- per-session keys derived with nonces  
- monotonically increasing session counters  

We use OpenSSL's `RAND_bytes`, `HMAC`, and `CRYPTO_memcmp` for secure randomness, authentication, and constant-time comparison.

---

## Files Created By The System

### `<init-fname>.bank`

Contains:

- one 64-character hex string representing a 32-byte master key  

Used by the bank to authenticate setup and session traffic.  
Only the bank can read this file.

### `<init-fname>.atm`

Contains:

- the same 64-character hex master key  

Used by the ATM to authenticate communication with the bank.  
Only the ATM can read this file.

### `<user-name>.card`

Contains:

- line 1: username  
- line 2: 64-character hex card secret  

This is the **"something you have"** factor.  
The file is created once and never modified.

The ATM reads it at session start, and the bank keeps the same secret in memory.

---

## Bank Account State

For each user, the bank stores:

- username  
- PIN  
- balance  
- card secret  
- active session flag  
- current session key  
- last accepted counter  

State is stored only in memory, which is allowed by the project spec.

---

## Cryptographic Design

### Master key

`init` generates a random 32-byte master key and writes it to both initialization files.  
The key is never sent over the network.

### Card secret

When `create-user` runs, the bank generates a new random 32-byte card secret, stores it in memory, and writes it to the user's `.card` file.

### Login authentication

Login requires:

- master key  
- correct PIN  
- correct card secret  

The ATM never sends the PIN or card secret directly.  
Instead, it computes an HMAC over:

- username  
- PIN  
- card secret  
- client nonce  

The bank recomputes the same value and compares it.  
Login succeeds only if they match.

### Session key derivation

After login, the bank sends a server nonce.  
Both sides derive:

HMAC(master_key, “SESSION|username|pin|card_secret|client_nonce|server_nonce”)

Each session gets a fresh key because the nonces change every time.

### Session message authentication

Every command after login includes:

- command  
- arguments  
- session counter  
- HMAC(session_key, message)

The bank verifies the MAC and requires the counter to strictly increase.  
This prevents tampering and replay.

---

## Message Formats

All ATM-bank protocol messages are ASCII fields separated by spaces.  
Hex strings are lowercase.

### User existence check

ATM to bank:

`EXISTS <user> <client_nonce_hex> <mac>`

where:

`mac = HMAC(master_key, "EXISTS|user|client_nonce_hex")`

Bank to ATM if the user exists:

`EXISTS_OK <client_nonce_hex> <mac>`

where:

`mac = HMAC(master_key, "EXISTS_OK|user|client_nonce_hex")`

Bank to ATM if the user does not exist:

`EXISTS_NO <client_nonce_hex> <mac>`

where:

`mac = HMAC(master_key, "EXISTS_NO|user|client_nonce_hex")`

### Login

ATM to bank:

`AUTH <user> <client_nonce_hex> <mac>`

where:

`mac = HMAC(master_key, "AUTH|user|pin|card_secret_hex|client_nonce_hex")`

The PIN and card secret are authenticated but are not sent as plaintext fields.

Bank to ATM on success:

`AUTH_OK <server_nonce_hex> <mac>`

where:

`mac = HMAC(master_key, "AUTH_OK|user|pin|card_secret_hex|client_nonce_hex|server_nonce_hex")`

Bank to ATM on failure:

`AUTH_FAIL`

The ATM treats `AUTH_FAIL` and any invalid login response as a failed authorization.

### Balance

ATM to bank:

`BALANCE <counter> <mac>`

where:

`mac = HMAC(session_key, "BALANCE|counter")`

Bank to ATM:

`BALANCE <amount> <counter> <mac>`

where:

`mac = HMAC(session_key, "BALANCE|amount|counter")`

### Withdraw

ATM to bank:

`WITHDRAW <amount> <counter> <mac>`

where:

`mac = HMAC(session_key, "WITHDRAW|amount|counter")`

Bank to ATM on success:

`DISPENSE <amount> <counter> <mac>`

where:

`mac = HMAC(session_key, "DISPENSE|amount|counter")`

Bank to ATM on insufficient funds:

`INSUFFICIENT <counter> <mac>`

where:

`mac = HMAC(session_key, "INSUFFICIENT|counter")`

### End session

ATM to bank:

`END <counter> <mac>`

where:

`mac = HMAC(session_key, "END|counter")`

Bank to ATM:

`END_OK <counter> <mac>`

where:

`mac = HMAC(session_key, "END_OK|counter")`

---

## Command Processing

### `create-user`

The bank:

1. Validates input  
2. Rejects duplicates  
3. Generates a card secret  
4. Stores the account  
5. Writes `<user>.card`  
6. Rolls back if file creation fails  

### `begin-session`

The ATM:

1. Validates username  
2. Checks user existence with the bank  
3. Reads the `.card` file  
4. Prompts for PIN  
5. Sends authenticated login request  
6. On valid `AUTH_OK`, derives the session key and logs in  

### `balance`

The ATM sends:

BALANCE counter mac

The bank accepts only if:

- session is active  
- MAC is valid  
- counter increased  

Then it returns the authenticated balance.

### `withdraw`

The ATM sends an authenticated withdraw request.  
The bank verifies the request and returns:

- `DISPENSE` if funds exist  
- `INSUFFICIENT` otherwise  

### `end-session`

Both sides clear session state after an authenticated `END` message.

---

## Threats And Countermeasures

### 1. Packet tampering

**Attack**

An attacker modifies packets, like changing `$20` to `$200`.

**Mitigation**

- setup requests and successful/user-existence setup responses use HMAC authentication under the master key  
- all in-session messages use HMAC under the session key  
- invalid MACs are rejected  

**Status**

Implemented.

---

### 2. Forged packets

**Attack**

The router sends fake commands.

**Mitigation**

- setup messages require the master key  
- login requires the correct PIN and card secret  
- session commands require the session key  

**Status**

Implemented.

---

### 3. Replay attacks

**Attack**

An attacker replays a valid withdraw request.

**Mitigation**

- every message includes a counter  
- counters must strictly increase  

**Status**

Implemented.

---

### 4. Login with only one factor

**Attack**

Attacker knows only the PIN or only the card.

**Mitigation**

The login HMAC depends on both values.  
Neither factor alone is enough.

**Status**

Implemented.

---

### 5. Reusing old sessions

**Attack**

Attacker replays traffic from a previous session.

**Mitigation**

Session keys depend on fresh client and server nonces.  
Each login creates a new key.

**Status**

Implemented.

---

### 6. Timing attacks on MAC comparison

**Attack**

Attacker measures response timing to guess MAC bytes.

**Mitigation**

We use `CRYPTO_memcmp` for constant-time comparison.

**Status**

Implemented.

---

## Threats Not Fully Addressed

### No confidentiality

Messages are authenticated but not encrypted.  
An attacker can still see:

- usernames  
- balances  
- withdrawal amounts  

This leaks information but does not allow forgery.  
A stronger design would use authenticated encryption.

### No persistence

All state is in memory.  
Restarting the bank clears accounts.

### PIN brute force

The system does not lock accounts after repeated failed PIN attempts.  
This keeps the ATM behavior simple and avoids denying access to a legitimate user, but a stronger design would add rate limiting or lockout.

### Single session assumption

We assume only one ATM session at a time, which is allowed by the assignment.

---

## Summary

The protocol uses shared secrets, per-user card secrets, authenticated messages, fresh session keys, and counters to prevent tampering, forgery, and replay. This directly addresses the main threat model: a malicious router that controls the network but cannot read protected files or process memory.
