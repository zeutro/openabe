from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
import os, sys

__version__ = "1.0.0"
os_platform = sys.platform
ZROOT_DIR = os.environ.get('ZROOT')
ZML_LIB = os.environ.get('ZML_LIB')
if (ZROOT_DIR is None): 
    sys.exit("Need to source env via '. ./env' in root directory")
print("ZROOT_DIR: ", ZROOT_DIR)
print("ZML_LIB: ", ZML_LIB)
if ZML_LIB and ZML_LIB == "with_openssl":
   with_openssl = True
else:
   with_openssl = False

_extra_objects = []
if "darwin" in os_platform:
    _extra_objects=[ZROOT_DIR + "/root/lib/libopenabe.a", "-lpthread"]
    _extra_compile_args = []
    if with_openssl:
        _extra_compile_args += ["-DBP_WITH_OPENSSL"]
    else:
        # add relic
        _extra_compile_args += ["-Wno-implicit-function-declaration", "-Wno-macro-redefined"]
        _extra_objects += ["-lrelic", "-lrelic_ec"]
elif "linux" in os_platform:
    _extra_objects=["-lopenabe", "-lpthread"]
    _extra_compile_args = []
    if with_openssl:
        _extra_compile_args += ["-DBP_WITH_OPENSSL"]
    else:
        # add relic
        _extra_compile_args += ["-Wno-implicit-function-declaration", "-Wno-macro-redefined"]
        _extra_objects += ["-lrelic", "-lrelic_ec"]

    _extra_compile_args=["-Wall", "-Wtype-limits"]
else:
    sys.exit("Your '%s' platform is currently unsupported." % os_platform)

_extra_objects += ["-lgmp", "-lssl", "-lcrypto"]
ext_modules = [Extension("pyopenabe",
             ["pyopenabe.pyx"],
             language='c++',
             extra_objects=_extra_objects,
             include_dirs=[ZROOT_DIR + "/deps/root/include", ZROOT_DIR + "/root/include"],
             library_dirs=[ZROOT_DIR + "/deps/root/lib", ZROOT_DIR + "/root/lib"],
             extra_compile_args=["-std=c++11", "-Wno-unused-function", "-DGTEST_USE_OWN_TR1_TUPLE=1",
                                 "-Wno-deprecated", "-pthread"] + _extra_compile_args
             )]

setup(
  name = 'pyopenabe',
  cmdclass = {'build_ext': build_ext},
  ext_modules = ext_modules,
  version = __version__
)
