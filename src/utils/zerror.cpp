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
/// \file   zerror.cpp
///
/// \brief  Class implementation for error codes to strings.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __ZTOOLKIT_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>

using namespace std;

/*!
 * Convert a OpenABE_ERROR result into a string.
 *
 * @param       The error code
 * @return      The error string
 */
namespace oabe {

const char *OpenABE_errorToString(OpenABE_ERROR error) {
    switch (error) {
      case OpenABE_NOERROR:
        return "No error";
        break;
      case OpenABE_ERROR_INVALID_CONTEXT:
        return "Invalid encryption context";
        break;
      case OpenABE_ERROR_INVALID_CIPHERTEXT:
        return "Invalid ciphertext";
        break;
      case OpenABE_ERROR_INVALID_GROUP_PARAMS:
        return "Invalid group parameters";
        break;
      case OpenABE_ERROR_INVALID_PARAMS:
        return "Invalid global parameters";
        break;
      case OpenABE_ERROR_INVALID_KEY:
        return "Invalid key or parameters";
        break;
      case OpenABE_ERROR_OUT_OF_MEMORY:
        return "Out of memory";
        break;
      case OpenABE_ERROR_INVALID_INPUT:
        return "Invalid function input";
        break;
      case OpenABE_ERROR_ENCRYPTION_ERROR:
        return "Error occurred during encryption";
        break;
      case OpenABE_ERROR_UNKNOWN_SCHEME:
        return "Unknown scheme";
        break;
      case OpenABE_ERROR_LIBRARY_NOT_INITIALIZED:
        return "Library not initialized or shut down due to critical error";
        break;
      case OpenABE_ERROR_NO_SECRET_PARAMS:
        return "Secret parameters are not available";
        break;
      case OpenABE_ERROR_NO_PUBLIC_PARAMS:
        return "Public parameters (MPK) are not available";
        break;
      case OpenABE_ERROR_NOT_IMPLEMENTED:
        return "Functionality has not been implemented";
        break;
      case OpenABE_ERROR_BUFFER_TOO_SMALL:
        return "Buffer is too small for the requested operation";
        break;
      case OpenABE_ERROR_INVALID_PARAMS_ID:
        return "Invalid group parameters ID";
        break;
      case OpenABE_ERROR_WRONG_GROUP:
        return "Input value is in the wrong group";
        break;
      case OpenABE_ERROR_ELEMENT_NOT_FOUND:
        return "Element not found in container";
        break;
      case OpenABE_ERROR_SECRET_SHARING_FAILED:
        return "Unable to complete secret sharing or recovery";
        break;
      case OpenABE_ERROR_INVALID_POLICY:
        return "Invalid policy";
        break;
      case OpenABE_ERROR_WRONG_USER_PARAM:
        return "Provided wrong user parameters";
        break;
      case OpenABE_ERROR_INVALID_LENGTH:
        return "Specified length is invalid";
        break;
      case OpenABE_ERROR_INVALID_TAG_LENGTH:
        return "Specified an invalid authentication tag length";
        break;
      case OpenABE_ERROR_SERIALIZATION_FAILED:
        return "Error occurred during serialization";
        break;
      case OpenABE_ERROR_INVALID_LIBVERSION:
        return "Input structure does not match library version";
        break;
      case OpenABE_ERROR_RAND_INSUFFICIENT:
        return "Insufficient randomness returned";
        break;
      case OpenABE_ERROR_UNEXPECTED_EXTRA_BYTES:
        return "Unexpected extra bytes were added beyond the size of the buffer";
        break;
      case OpenABE_ERROR_IN_USE_ALREADY:
        return "Specified identifier is currently in use already";
        break;
      case OpenABE_ERROR_INVALID_KEY_HEADER:
        return "Error occurred while parsing the key header. Perhaps, key type "
               "mismatch?";
        break;
      case OpenABE_ERROR_INVALID_CIPHERTEXT_HEADER:
        return "Error occurred while parsing the ciphertext header";
        break;
      case OpenABE_ERROR_DECRYPTION_FAILED:
        return "Error occurred during decryption";
        break;
      case OpenABE_ERROR_VERIFICATION_FAILED:
        return "Could not perform verification due to invalid inputs or "
               "verification failed";
        break;
      case OpenABE_ERROR_DIVIDE_BY_ZERO:
        return "Divide by zero error occurred";
        break;
      case OpenABE_ERROR_ORDER_NOT_SPECIFIED:
        return "The order of the group was not specified";
        break;
      case OpenABE_ERROR_ELEMENT_NOT_INITIALIZED:
        return "The group or integer element was not initialized";
        break;
      case OpenABE_ERROR_DESERIALIZATION_FAILED:
        return "Error occurred during deserialization";
        break;
      case OpenABE_ERROR_INVALID_CURVE_ID:
        return "Invalid curve identifier";
        break;
      case OpenABE_ERROR_INVALID_SCHEME_ID:
        return "Invalid scheme identifier";
        break;
      case OpenABE_ERROR_INVALID_KEY_BODY:
        return "The body of the key structure is malformed";
        break;
      case OpenABE_ERROR_INVALID_CIPHERTEXT_BODY:
        return "The body of the ciphertext is malformed";
        break;
      case OpenABE_ERROR_SYNTAX_ERROR_IN_PARSER:
        return "A syntax error occurred during parsing of the input policy";
        break;
      case OpenABE_ERROR_CTR_DRB_NOT_INITIALIZED:
        return "The CTR DRBG context was not initialized. Failed to call 'setSeed'";
        break;
      case OpenABE_ERROR_CLASS_NOT_INITIALIZED:
        return "The object was not initialized properly";
        break;
      case OpenABE_ERROR_INVALID_PACK_TYPE:
        return "The pack type specified is invalid";
        break;
      case OpenABE_ERROR_INVALID_ATTRIBUTE_STRUCTURE:
        return "Invalid attribute structure specified";
        break;
      case OpenABE_ERROR_INDEX_OUT_OF_BOUNDS:
        return "Index is out of bounds";
        break;
      case OpenABE_ERROR_MISSING_SENDER_PUBLIC_KEY:
        return "Missing the sender's public key";
        break;
      case OpenABE_ERROR_MISSING_RECEIVER_PRIVATE_KEY:
        return "Missing the receiver's private key";
        break;
      case OpenABE_ERROR_MISSING_RECEIVER_PUBLIC_KEY:
        return "Missing the receiver's public key";
        break;
      case OpenABE_ERROR_MISSING_AUTHORITY_ID_IN_ATTR:
        return "Missing authority ID in specified attribute";
        break;
      case OpenABE_ERROR_INVALID_ATTRIBUTE_LIST:
        return "Invalid attribute list specified";
        break;
      case OpenABE_ERROR_INVALID_RANGE_NUMBERS:
        return "Invalid range numbers specified";
        break;
      case OpenABE_ERROR_INVALID_MISMATCH_BITS:
        return "Specified a mismatch of integer bits";
        break;
      case OpenABE_ERROR_INVALID_PREFIX_SPECIFIED:
        return "Specified a reserved/system prefix";
        break;
      case OpenABE_ERROR_INVALID_DATE_SPECIFIED:
        return "Invalid date specified as attribute";
        break;
      case OpenABE_ERROR_INVALID_DATE_BEFORE_EPOCH:
        return "Date specified is before unix epoch: January 1, 1970";
        break;
      case OpenABE_ERROR_SIGNATURE_FAILED:
        return "Error occurred during signing";
        break;
      case OpenABE_ERROR_KEYGEN_FAILED:
        return "Error occurred during key generation";
        break;
      case OpenABE_ERROR_NO_PLAINTEXT_SPECIFIED:
        return "Did not specify plaintext to encrypt or sign";
      case OpenABE_ERROR_UNKNOWN:
        return "Unknown error";
        break;
      default:
        return "Unrecognized error code";
        break;
      }
    }
}
