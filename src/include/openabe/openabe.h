/// 
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
/// 
/// This file is part of Zeutro's OpenABE.
/// 
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
/// 
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
/// 
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
/// 
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
/// \file   openabe.h
///
/// \brief  Main header file for the Zeutro Toolkit (OpenABE).
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZTOOLKIT_H__
#define __ZTOOLKIT_H__

#include <cstdint>
#include <string>

#define SAFE_MALLOC(size) malloc(size)
#define SAFE_FREE(val) free(val)
#define SAFE_DELETE(ref)                                                       \
  if (ref != NULL) {                                                           \
    delete ref;                                                                \
    ref = NULL;                                                                \
  }

#define OpenABE_LOG_ERROR(str) (std::cerr << "ERROR: " << str << std::endl)

#ifdef DEBUG
 #define DEBUG_ELEMENT_PRINTF(...) element_printf(__VA_ARGS__)
 #define OpenABE_LOG_AND_THROW(str, err)                                            \
  OpenABE_LOG_ERROR((str));                                                        \
  throw(err);
#define OpenABE_LOG(str)                                                           \
  OpenABE_LOG_ERROR((str));

#else
 #define DEBUG_ELEMENT_PRINTF(...)
 #define OpenABE_LOG_AND_THROW(str, err)                                            \
  throw(err);
 #define OpenABE_LOG(str) /* do nothing */
#endif

/// @typedef    OpenABE_STATE
///
/// @brief      Enumeration of global states for the Zeutro toolkit library

typedef enum _OpenABE_STATE {
  OpenABE_STATE_UNINITIALIZED = 0,
  OpenABE_STATE_ERROR = 1,
  OpenABE_STATE_READY = 2
} OpenABE_STATE;

/// @typedef    OpenABE_SCHEME
///
/// @brief      Enumeration of supported FE schemes

typedef enum _OpenABE_SCHEME {
  OpenABE_SCHEME_NONE = 0,
  OpenABE_SCHEME_PKSIG_ECDSA = 60,
  OpenABE_SCHEME_AES_GCM = 70,
  OpenABE_SCHEME_PK_OPDH = 100,
  OpenABE_SCHEME_CP_WATERS = 101,
  OpenABE_SCHEME_KP_GPSW = 102,
  OpenABE_SCHEME_CP_WATERS_CCA = 201,
  OpenABE_SCHEME_KP_GPSW_CCA = 202
} OpenABE_SCHEME;

//
// hash function prefix definitions
#define CCA_HASH_FUNCTION_ONE 0x1A
#define CCA_HASH_FUNCTION_TWO 0x1F
#define SCHEME_HASH_FUNCTION 0x2A
#define KDF_HASH_FUNCTION_PREFIX 0x2B

#define OpenABE_MAX_KDF_BITLENGTH 0xFFFFFFFF
//
// Types and data structures
//

typedef uint32_t OpenABESecurityLevel;

//
// Core library header files
//

#include <openabe/zobject.h>
#include <openabe/utils/zconstants.h>
#include <openabe/utils/zbytestring.h>
#include <openabe/utils/zfunctioninput.h>
#include <openabe/utils/zpolicy.h>
#if defined(OS_REDHAT_LINUX)
   #include <cstddef>
   #include <cstdio>
   using ::max_align_t;
#endif
#include <gmpxx.h>
extern "C" {
#include <openabe/zml/zelement.h>
}
#include <openabe/zml/zgroup.h>
#include <openabe/zml/zelement_bp.h>
#include <openabe/zml/zelement_ec.h>
#include <openabe/zml/zelliptic.h>
#include <openabe/zml/zpairing.h>
#include <openabe/tools/zprng.h>
#include <openabe/utils/zexception.h>
#include <openabe/utils/zcryptoutils.h>
#include <openabe/utils/zinteger.h>
#include <openabe/utils/zcontainer.h>
#include <openabe/utils/zciphertext.h>
#include <openabe/utils/zattributelist.h>
#include <openabe/keys/zkey.h>
#include <openabe/keys/zpkey.h>
#include <openabe/keys/zsymkey.h>
#include <openabe/keys/zkeystore.h>
#include <openabe/tools/zlsss.h>
#include <openabe/keys/zkdf.h>
#include <openabe/zcontext.h>
#include <openabe/low/ske/zcontextske.h>
#include <openabe/low/pke/zcontextpke.h>
#include <openabe/low/pksig/zcontextpksig.h>
#include <openabe/zcontextabe.h>
#include <openabe/zsymcrypto.h>
#include <openabe/zcontextcca.h>
#include <openabe/low/abe/zcontextcpwaters.h>
#include <openabe/low/abe/zcontextkpgpsw.h>
#include <openabe/utils/zdriver.h>
#include <openabe/utils/zkeymgr.h>
#include <openabe/utils/zx509.h>
#include <openabe/zcrypto_box.h>

namespace oabe {

#if defined(BP_WITH_OPENSSL)
const std::string DEFAULT_MATH_LIB = "OpenSSL";
#else /* WITH RELIC */
const std::string DEFAULT_MATH_LIB = "RELIC";
#endif
const std::string DEFAULT_BP_PARAM = "BN_P254";
//const std::string DEFAULT_BP_PARAM = "BN_P382";
const std::string DEFAULT_EC_PARAM = "NIST_P256";

///
/// scheme identifiers
///

#define OpenABE_EC_DSA "EC-DSA"
#define OpenABE_PK_ENC "PK-ENC"
#define OpenABE_CP_ABE "CP-ABE"
#define OpenABE_KP_ABE "KP-ABE"
#define OpenABE_MA_ABE "MA-ABE"

///
/// Utility functions
///

void InitializeOpenABE();
void InitializeOpenABEwithoutOpenSSL();
void ShutdownOpenABE();
void AssertLibInit();

const char *OpenABE_errorToString(OpenABE_ERROR err);
const uint32_t OpenABE_getLibraryVersion();

// creates KEM context for PKE & ABE schemes
OpenABEContextPKE *OpenABE_createContextPKE(std::unique_ptr<OpenABERNG> *rng,
                                    OpenABE_SCHEME scheme_type);
OpenABEContextABE *OpenABE_createContextABE(std::unique_ptr<OpenABERNG> *rng,
                                    OpenABE_SCHEME scheme_type);

// PKE scheme context API
std::unique_ptr<OpenABEContextSchemePKE>
OpenABE_createContextPKESchemeCCA(OpenABE_SCHEME scheme_type);
std::unique_ptr<OpenABEContextCCA>
OpenABE_createABEContextForKEM(OpenABE_SCHEME scheme_type);

// CPA scheme context API
std::unique_ptr<OpenABEContextSchemeCPA>
OpenABE_createContextABESchemeCPA(OpenABE_SCHEME scheme_type);

// CCA scheme context API
std::unique_ptr<OpenABEContextSchemeCCA>
OpenABE_createContextABESchemeCCA(OpenABE_SCHEME scheme_type);

// CCA scheme context API with amortization support
std::unique_ptr<OpenABEContextSchemeCCAWithATZN>
OpenABE_createContextABESchemeCCAWithATZN(OpenABE_SCHEME scheme_type);

// PKSIG scheme context API
std::unique_ptr<OpenABEContextSchemePKSIG> OpenABE_createContextPKSIGScheme();

// curve to/from string conversion functions
OpenABECurveID OpenABE_getCurveID(uint8_t id);
OpenABE_SCHEME OpenABE_getSchemeID(uint8_t id);
// convert strings to/from OpenABE_SCHEME
const std::string OpenABE_convertSchemeIDToString(OpenABE_SCHEME schemeID);
OpenABE_SCHEME OpenABE_convertStringToSchemeID(const std::string id);

OpenABECurveID OpenABE_convertStringToCurveID(const std::string paramsID);
std::string OpenABE_convertCurveIDToString(OpenABECurveID id);
void OpenABE_setGroupObject(std::shared_ptr<ZGroup> &group, uint8_t id);

///
/// OpenABE initialization per thread
///
class OpenABEStateContext {
public:
  /*! \brief Initialize OpenABE per thread
   *
   * The following function needs to be called exactly once at the
   * beginning of any OpenABE-using thread except for the thread that
   * calls OpenABE_initialize.  This must be done in a thread before any
   * OpenABE functionality is invoked in that thread, otherwise, your
   * program may crash arbitrarily.
   */
  void initializeThread();

  /*! \brief Shutdown OpenABE per thread
   *
   * The following function needs to be called exactly once at the
   * end of any OpenABE-using thread except for the thread that calls
   * OpenABE_shutdown.  This should be done before the destruction of
   * the thread. If you forget to call this function, it is invoked
   * in the destructor of the OpenABE state context.
   */
  void shutdownThread();

  OpenABEStateContext() : isInitialized_(false) {
    // initializeThread() on constructor initialization
    initializeThread();
    isInitialized_ = true;
  }

  ~OpenABEStateContext() {
    // in case user forgets to call shutdownThread()
    if (isInitialized_) {
      shutdownThread();
    }
  }

private:
  bool isInitialized_;
};
}

#endif /* __ZTOOLKIT_H__ */
