My break-it attack against `break-it/6825f15e/`.

`VULNERABILITY-ANALYSIS.md` is the actual documentation I submitted on ELMS.
`router-main.c` is a drop-in replacement for `../router/router-main.c`

It forwards everything untouched but discreetly logs the plaintext. The Makefile
builds it against the unmodified `../router/router.c` and swaps it in for
`../bin/router`. `run-demo.sh` is the end-to-end demo that spins up init, the
malicious router, the bank, and the ATM, walks through a normal session, and
prints what each side saw.

To run it:

```sh
make
cd attack && make
cd ..
./attack/run-demo.sh
```
