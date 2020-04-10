This project implements some PGP functionality with the [Solo](https://github.com/solokeys/solo) key.
It is inspired by [this](https://boats.gitlab.io/blog/post/signing-commits-without-gpg/) blog post on how to sign git commits without GPG.
You also need my [custom](https://github.com/solokeys/solo/pull/397) Solo firmware which adds the ability to sign arbitrary SHA256 hashes.

Setup
---
Install the `fido2` Python library and export `SOLOPIN` with the PIN number of your Solo key.
The scripts are using credential management APIs and they all require a PIN set.

```bash
$ pip install fido2
$ export SOLOPIN=1234
```

Generating a new PGP key
---
Generated PGP keys are stored on the device as resident keys.

```bash
$ ./solo-pgp.py --gen-key
Real name: Radoslav Gerganov
Email address: rgerganov@gmail.com
Key ID: 7D3E453464BC08F3
Key fingerprint: A8104854A9E174FBDB63F58D7D3E453464BC08F3

-----BEGIN PGP PUBLIC KEY BLOCK-----

mFIEXpByABMIKoZIzj0DAQcCAwTjAA5C0WkWYzplWAD+yDCilwJnBM+YdeNmt93XA5x8yjeI3wm6
zbSJ/eblKEcjW0GW1h3XzyxhzsPj14qmI1iFtCdSYWRvc2xhdiBHZXJnYW5vdiA8cmdlcmdhbm92
QGdtYWlsLmNvbT6IeAQTEwgAIBYhBKgQSFSp4XT722P1jX0+RTRkvAjzAhsDBQJekHIAAAoJEH0+
RTRkvAjz6wwBALxro/0y+z9PIugtaY6abafMZJI13mH7HW0RK+wrNyOaAQC26FFNLDyE7KqxFHbZ
Adwb7G4eI7NseD7KJBpO3WCKlA==
-----END PGP PUBLIC KEY BLOCK-----
```

Listing existing keys
---

```bash
$ ./solo-pgp.py --list
Created: 2020-04-10 13:16:58
User: Radoslav Gerganov <rgerganov@vmware.com>
ID: 49103AEE98E03850
Fingerprint: FC6FE7B2779D9263405E3DC149103AEE98E03850

Created: 2020-04-10 13:17:52
User: Radoslav Gerganov <rgerganov@gmail.com>
ID: 7D3E453464BC08F3
Fingerprint: A8104854A9E174FBDB63F58D7D3E453464BC08F3
```

Exporting a public key
---
Public keys can be exported by key ID (8 bytes).

```bash
$ ./solo-pgp.py --export 49103AEE98E03850
-----BEGIN PGP PUBLIC KEY BLOCK-----

mFIEXpBxyhMIKoZIzj0DAQcCAwSVuooABrG6v9NX8CWwNTu/SoboDmJj+I/1sC1cfLkmrpn+aUqK
qM/tyY9e+nK/vZrMbuSdDVs9GeWvdMMygNo7tChSYWRvc2xhdiBHZXJnYW5vdiA8cmdlcmdhbm92
QHZtd2FyZS5jb20+iHgEExMIACAWIQT8b+eyd52SY0BePcFJEDrumOA4UAIbAwUCXpBxygAKCRBJ
EDrumOA4UDKVAPgA5CoOPIoMTzaPhhA1OsAhEI5Qb+Y/KzFLl4jkKA1o2wEA0ZrhS98u2vI0OkSf
A+U5Si0dDre+hWfLT2MZZjeGUiY=
-----END PGP PUBLIC KEY BLOCK-----
```

Creating detached ECDSA signature
---

```bash
$ echo 'Hello world!' | ./solo-pgp.py --sign 7D3E453464BC08F3 2>/dev/null
-----BEGIN PGP SIGNATURE-----

iHUEABMIAB0WIQSoEEhUqeF0+9tj9Y19PkU0ZLwI8wUCXpBzngAKCRB9PkU0ZLwI8xIOAQDfwdzN
KhTbnSuWIkeq8AGfL9IWM5c2Yu5diG9wXOM9JgD8DJP7ru01pdbGh1Z5zitXt8LW8LF8yDSVOz+X
Z9wVDU0=
-----END PGP SIGNATURE-----
```

Signing Git commits
---
You need to tell Git the key ID that you are going to use and then set `gpg.program` to point to `solo-git.py`.
When Git invokes `solo-git.py`, it will check if the operation is sign and use the Solo key if so.
Otherwise it will delegate to `gpg`.

```bash
$ git config user.signingkey 7D3E453464BC08F3
$ git config gpg.program /opt/src/solo-pgp/solo-git.py
# do stuff and finally commit with -S to sign
$ git commit -S
```
