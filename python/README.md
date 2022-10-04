# Python bindings for BS-SPEKE

## Build
To build the bindings, run `bsspeke_build.py`.  This will:

1. Run the `Makefile` to generate headers that Python's CFFI can understand
2. Use Python's CFFI to generate a low-level Python interface to the C library

## Run
See `cffi_demo.py` for an example of how you can use the low-level
CFFI bindings directly.

Alternatively, `BSSpeke.py` provides a more friendly high-level interface.
