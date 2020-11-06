# Simple KMU sample for the nRF9160 CC310

This sample demonstrates:

* Write a 128 bit AES key to a KMU slot.
  * This is typically done in production.
  * This code and the secret key must not remain in flash after the key has
    been written to the KMU (that would defeat the purpose of using the KMU).
* Use KMU key for crypto operations:
  * Push key to CryptoCell and
  * Use key to encrypt and decrypt a test vector using AES ECB.
  * This is typically done in the field and allows crypto operations without
    the CPU ever being able to access the key.

Notes:

* Only works in secure mode.
* Tested with NCS 1.4.0.
