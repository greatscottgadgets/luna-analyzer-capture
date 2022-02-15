from cffi import FFI

ffi = FFI()
ffi.cdef(open('library.h').read())
lib = ffi.dlopen('./library.so')

__all__ = dir(lib)

g = globals()
for name in __all__:
    g[name] = getattr(lib, name)
