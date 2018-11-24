# Author: J. Ayo Akinyele

from libcpp.string cimport string
from libcpp.set cimport set as cpp_set
from libcpp cimport bool
from cython.operator cimport dereference as deref

############################################# BEGIN C++ DEFINITIONS #############################################

# include unique_ptr and shared_ptr from std::memory
cdef extern from "<memory>" namespace "std":
    cdef cppclass unique_ptr[T]:
        unique_ptr() nogil
        unique_ptr(T*) nogil
        unique_ptr(unique_ptr&) nogil

        T* get() nogil
        T& operator*() nogil
        #T* operator->()
        T* release() nogil
        void reset(T*) nogil
        void reset() nogil

    cdef cppclass shared_ptr[T]:
        shared_ptr() nogil
        shared_ptr(T*) nogil
        void reset() nogil
        void reset(T*) nogil
        T& operator*() nogil
        T* get() nogil

# Include ABE functionality from OpenABE
cdef extern from "<openabe/openabe.h>" namespace "oabe":
    cdef enum _OpenABE_ERROR:
        OpenABE_NOERROR = 0
    ctypedef _OpenABE_ERROR OpenABE_ERROR
    cdef enum _OpenABEFunctionInputType:
        FUNC_INVALID_INPUT = 0
        FUNC_POLICY_INPUT = 1
        FUNC_ATTRLIST_INPUT = 2
    bool checkPassword(string&, string&) except +RuntimeError
    void InitializeOpenABE() except +RuntimeError
    void ShutdownOpenABE() except +RuntimeError
    cdef cppclass OpenABECryptoContext:
        OpenABECryptoContext(string scheme_id);
        void generateParams() except +RuntimeError
        void exportPublicParams(string& mpk)
        void exportSecretParams(string& msk)
        void importPublicParams(string& keyBlob)
        void importSecretParams(string& keyBlob)
        void importPublicParams(string& authID, string& keyBlob)
        void importSecretParams(string& authID, string& keyBlob)
        void importUserKey(string& keyID, string& keyBlob)
        void exportUserKey(string& keyID, string& keyBlob)
        void keygen(string& keyInput, string &keyID, string& authID, string &GID) except +RuntimeError
        void encrypt(string encInput, string& plaintext, string& ciphertext) except +RuntimeError
        bool decrypt(string& keyID, string& ciphertext, string& plaintext) except +RuntimeError
    cdef cppclass OpenPKEContext:
        OpenPKEContext(string ec_id)
        void exportPublicKey(string key_id, string& keyBlob)
        void exportPrivateKey(string key_id, string& keyBlob)
        void importPublicKey(string key_id, string& keyBlob)
        void importPrivateKey(string key_id, string& keyBlob)
        void keygen(string key_id) except +RuntimeError
        bool encrypt(string receiver_id, string& plaintext, string& ciphertext) except +RuntimeError
        bool decrypt(string receiver_id, string& ciphertext, string& plaintext) except +RuntimeError
    cdef cppclass OpenPKSIGContext:
        OpenPKSIGContext(string ec_id)
        void exportPublicKey(string key_id, string& keyBlob)
        void exportPrivateKey(string key_id, string& keyBlob)
        void importPublicKey(string key_id, string& keyBlob)
        void importPrivateKey(string key_id, string& keyBlob)
        void keygen(string key_id)
        void sign(string key_id, string& message, string& signature)
        bool verify(string key_id, string& message, string& signature)
    const char* OpenABE_errorToString(OpenABE_ERROR)

############################################# END C++ DEFINITIONS #############################################

########################################### BEGIN PYTHON WRAPPERS #############################################

class PyOpenABEError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

def to_bytes(obj):
    if type(obj) in [str, unicode]:
        try:
          enc_obj = obj.encode('UTF-8')
        except:
          return obj
        return enc_obj
    elif type(obj) == bytes:
        return obj
    else:
        raise PyOpenABEError("invalid string type: 'str' or 'bytes' allowed. Got '%s'" % type(obj))

########################################### PK ENC CONTEXT #############################################

# main wrapper for encryption/signature contexts
cdef class PyABEContext:
    cdef OpenABECryptoContext *thisptr
    def __cinit__(self, scheme):
        cdef string scheme_id = to_bytes(scheme)
        self.thisptr = new OpenABECryptoContext(scheme_id)

    def __dealloc__(self):
        del self.thisptr

    def generateParams(self):
        return self.thisptr.generateParams()

    def exportPublicParams(self):
        cdef string mpk = string(b"")
        self.thisptr.exportPublicParams(mpk)
        return mpk

    def exportSecretParams(self):
        cdef string msk = string(b"")
        self.thisptr.exportSecretParams(msk)
        return msk

    def importPublicParams(self, keyBlob):
        cdef string key = to_bytes(keyBlob)
        return self.thisptr.importPublicParams(key)

    def importPublicParams(self, authID, keyBlob):
        cdef string auth_id = to_bytes(authID)
        cdef string key = to_bytes(keyBlob)
        return self.thisptr.importPublicParams(auth_id, key)

    def importSecretParams(self, keyBlob):
        cdef string key = to_bytes(keyBlob)
        return self.thisptr.importSecretParams(key)

    def importSecretParams(self, authID, keyBlob):
        cdef string auth_id = to_bytes(authID)
        cdef string key = to_bytes(keyBlob)
        return self.thisptr.importSecretParams(auth_id, key)

    def importUserKey(self, keyID, keyBlob):
        cdef string key_id = to_bytes(keyID)
        cdef string key = to_bytes(keyBlob)
        return self.thisptr.importUserKey(key_id, key)

    def exportUserKey(self, keyID):
        cdef string key_id = to_bytes(keyID)
        cdef string key = string(b"")
        self.thisptr.exportUserKey(key_id, key)
        return key

    def keygen(self, keyInput, keyID, authID="", GID=""):
        cdef string key_input = to_bytes(keyInput)
        cdef string key_id = to_bytes(keyID)
        cdef string auth_id = to_bytes(authID)
        cdef string gid_id = to_bytes(GID)
        try:
            return self.thisptr.keygen(key_input, key_id, auth_id, gid_id)
        except RuntimeError as e:
            raise PyOpenABEError(str(e))

    def encrypt(self, encInput, plaintext):
        cdef string enc_input = to_bytes(encInput)
        cdef string pt = to_bytes(plaintext) # expected to be bytes
        cdef string ciphertext = string(b"")
        try:
            self.thisptr.encrypt(enc_input, pt, ciphertext)
            return ciphertext
        except RuntimeError as e:
            raise PyOpenABEError(str(e))

    def decrypt(self, keyID, ciphertext):
        cdef string key_id = to_bytes(keyID)
        cdef string pt = string(b"")
        cdef string ct = to_bytes(ciphertext)
        res = self.thisptr.decrypt(key_id, ct, pt)
        if res:
            return pt
        else:
            raise PyOpenABEError("Failed to decrypt!")

# class for PKE encryption
cdef class PyPKEContext:
    cdef OpenPKEContext *thisptr
    def __cinit__(self, curve_id="NIST_P256"):
        cdef string curve = to_bytes(curve_id)
        self.thisptr = new OpenPKEContext(curve)

    def __dealloc__(self):
        del self.thisptr

    def exportPublicKey(self, keyID):
        cdef string key_id = to_bytes(keyID)
        cdef string key = string(b"")
        self.thisptr.exportPublicKey(key_id, key)
        return key

    def exportPrivateKey(self, keyID):
        cdef string key_id = to_bytes(keyID)
        cdef string key = string(b"")
        self.thisptr.exportPrivateKey(key_id, key)
        return key

    def importPublicKey(self, keyID, keyBlob):
        cdef string key_id = to_bytes(keyID)
        cdef string key = to_bytes(keyBlob)
        return self.thisptr.importPublicKey(key_id, key)

    def importPrivateKey(self, keyID, keyBlob):
        cdef string key_id = to_bytes(keyID)
        cdef string key = to_bytes(keyBlob)
        return self.thisptr.importPrivateKey(key_id, key)

    def keygen(self, keyID):
        cdef string key_id = to_bytes(keyID)
        return self.thisptr.keygen(key_id)

    def encrypt(self, receiver_id, pt):
        cdef string rec_id = to_bytes(receiver_id)
        cdef string pt_str = pt # expected to be bytes
        cdef string ct = string(b"")
        res = self.thisptr.encrypt(rec_id, pt_str, ct)
        if res:
            return ct
        else:
            raise PyOpenABEError("Failed to encrypt")

    def decrypt(self, receiver_id, ciphertext):
        cdef string rec_id = to_bytes(receiver_id)
        cdef string ct = to_bytes(ciphertext)
        cdef string pt_str = string(b"")
        res = self.thisptr.decrypt(rec_id, ct, pt_str)
        if res:
            return pt_str
        else:
            raise PyOpenABEError("Failed to encrypt")

# class for PKSig
cdef class PyPKSIGContext:
    cdef OpenPKSIGContext *thisptr
    def __cinit__(self, curve_id="NIST_P256"):
        cdef string curve = to_bytes(curve_id)
        self.thisptr = new OpenPKSIGContext(curve)

    def __dealloc__(self):
        del self.thisptr

    def exportPublicKey(self, keyID):
        cdef string key_id = to_bytes(keyID)
        cdef string key = string(b"")
        self.thisptr.exportPublicKey(key_id, key)
        return key

    def exportPrivateKey(self, keyID):
        cdef string key_id = to_bytes(keyID)
        cdef string key = string(b"")
        self.thisptr.exportPrivateKey(key_id, key)
        return key

    def importPublicKey(self, keyID, keyBlob):
        cdef string key_id = to_bytes(keyID)
        cdef string key = to_bytes(keyBlob)
        return self.thisptr.importPublicKey(key_id, key)

    def importPrivateKey(self, keyID, keyBlob):
        cdef string key_id = to_bytes(keyID)
        cdef string key = to_bytes(keyBlob)
        return self.thisptr.importPrivateKey(key_id, key)

    def keygen(self, keyID):
        cdef string key_id = to_bytes(keyID)
        return self.thisptr.keygen(key_id)

    def sign(self, keyID, message):
        cdef string key_id = to_bytes(keyID)
        cdef string msg = to_bytes(message)
        cdef string sig = string(b"")
        try:
            self.thisptr.sign(key_id, msg, sig)
            return sig.decode('UTF-8')
        except RuntimeError as e:
            raise PyOpenABEError(str(e))

    def verify(self, keyID, message, signature):
        cdef string key_id = to_bytes(keyID)
        cdef string msg = to_bytes(message)
        cdef string sig = to_bytes(signature)
        return self.thisptr.verify(key_id, msg, sig)

########################################### CREATE OpenABE CONTEXTS #############################################

# OpenABE wrapper for all encryption/signature contexts
cdef class PyOpenABE: 
    def __cinit__(self):
        # Implicitly initializes OpenSSL too
        InitializeOpenABE() 

    def __dealloc__(self):
        ShutdownOpenABE()

    def getSchemeTypes(self):
        return ["CP-ABE", "KP-ABE"]

    def CreateABEContext(self, scheme):
        return PyABEContext(scheme)

    def CreatePKEContext(self):
        return PyPKEContext()

    def CreatePKSIGContext(self):
        return PyPKSIGContext()

########################################### END PYTHON WRAPPERS #############################################
