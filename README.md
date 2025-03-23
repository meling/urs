Unique Ring Signatures (URS)
============================

URS can be used to sign messages anonymously (among a group of known users).
That is a user can sign a message, hiding among a group of known/registered
users, that prevents the verifier from revealing the signer's identity other
than knowing that it is in the set of registered users. The size of the set of
registered users is flexible. Increasing this number slows down signing and
verifying linearly.

## Vulnerability Warning: Do not use this library

See the issue tracker for details.
