# BS-SPEKE

## Build

To build the C library and a simple C demo program, run `make` in the top-level directory.

## Python

To build the Python interface, run `bsspeke_build.py` in the `python` subdirectory.

```console
$ cd python
$ python3 bsspeke_build.py
```

### Running the Swiclops tests
The `python` subdirectory contains three files for testing against the
BS-SPEKE module for Matrix user-interactive authentication in
[Swiclops](https://github.com/circles-project/swiclops.git).

The Swiclops test scripts take two command-line parameters: (1) the Matrix domain
of the server where Swiclops is running, and (2) the email address to use for
Swiclops's email verification.

For example, you can run the test that registers a new user and then logs them in:

```console
$ python3 swiclops_register_bsspeke_and_login.py example.com user@example.com
```
