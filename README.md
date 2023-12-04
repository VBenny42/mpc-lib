# CSCD71 Final Project - Fireblocks-MPC

By: Maaz Hashmi & Vinesh Benny

## On branch `main-signing`:

- Run `sh run-docker.sh` to run the docker container
- Inside the container, `cd signing-test` then do `make run`
- This should run our test file `main.cpp`, found under `mpc/signing_test`

## On branch `python-verify`:

- First we ran a test with 2 players as described above and got test signatures for `r`, `s` and the `derived_public_key` for our mock message.
- Goal was to verify this signature using the `ecdsa` module in python.
- There are two python files under `signing_test`: `verify.py` and `pubkey_verify.py` for the two approaches we took to try and verify our signature.
- `verify.py` tries to verify the signature using our test information and the ecdsa module. But it outputs invalid signature so somethings not working.
- `pubkey_verify.py` tries to use the `r` and `s` signatures from the test and the signed messaged to generate the `derived_pub_key`. It successfully generates a public key but this still doesn't match the public key in our test so something is not working here as well.
