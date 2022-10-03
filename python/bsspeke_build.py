from cffi import FFI
import subprocess

print("Initializing FFI builder")
ffibuilder = FFI()

compile_args = ["-I./include"]
link_args = ["-L.."]

# cvw: Borrowed this trick from libolm :)
print("Making headers")
headers_build = subprocess.Popen("make headers", shell=True)
headers_build.wait()

# cdef() expects a single string declaring the C types, functions and
# globals needed to use the shared object. It must be in valid C syntax.
#ffibuilder.cdef("""
#    float pi_approx(int n);
#""")
print("Running FFI builder cdef")
with open("include/bsspeke.h") as f:
    ffibuilder.cdef(f.read())

# set_source() gives the name of the python extension module to
# produce, and some C source code as a string.  This C code needs
# to make the declarated functions, types and globals available,
# so it is often just the "#include".
print("Running FFI builder set_source")
ffibuilder.set_source("_bsspeke_cffi",
"""
     #include "bsspeke.h"   // the C header of the library
""",
     libraries=['bsspeke'],   # library name, for the linker
     extra_compile_args=compile_args,
     extra_link_args=link_args)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
