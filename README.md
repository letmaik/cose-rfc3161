# cose-rfc3161

This is a small demo showing how RFC 3161 time-stamping can be used to time-stamp COSE signatures as described at https://datatracker.ietf.org/doc/draft-birkholz-cose-tsa-tst-header-parameter/.

NOTE: This is not production code! Use at your own risk.

Sample output:

```
$ ./run.sh 
Setting up python virtual environment.
Running test.
Creating COSE_Sign1 message
Generating ephemeral private key to sign COSE_Sign1 message
Signing COSE_Sign1 message
Size of COSE message: 88 bytes
Time-stamping COSE signature with http://freetsa.org/tsr
Size of COSE message (with time-stamp token): 1421 bytes
Verifying embedded time-stamp token in COSE_Sign1
Token is valid, signature was created before:
2022-09-06 13:33:55
```
