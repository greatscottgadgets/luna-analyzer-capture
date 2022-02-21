from cffi import FFI

ffi = FFI()
ffi.cdef(open('library.h').read(), packed=True)
lib = ffi.dlopen('./library.so')

__all__ = dir(lib)

g = globals()
for name in __all__:
    g[name] = getattr(lib, name)

pid_names = [
        "RSVD", "OUT", "ACK", "DATA0",
        "PING", "SOF", "NYET", "DATA2",
        "SPLIT", "IN", "NAK", "DATA1",
        "ERR", "SETUP", "STALL", "MDATA"]

__all__ += ['pid_names']
