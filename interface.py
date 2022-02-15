from cffi import FFI

def load_capture():
    ffi = FFI()
    ffi.cdef(open('library.h').read())
    lib = ffi.dlopen('./library.so')
    return lib.load_capture()
