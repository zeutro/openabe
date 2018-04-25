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
/// \file   common.cpp
///
/// \brief  Common routines and shared functionality
///
/// \author J. Ayo Akinyele
///

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <climits>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>

#define DEFAULT_PARAMETER_STRING    DEFAULT_BP_PARAM // "BN_P256"
#define DEFAULT_NIST_PARAM_STRING   DEFAULT_EC_PARAM // "NIST_P256"
#define OpenABE_CLI_STRING          "OpenABE command-line: "

//#define	DEFAULT_SECURITY_LEVEL	128
//#define	SYM_KEY_BYTES		16
#define MAX_FILE_SIZE   ULONG_MAX  /* up to 4GB (or 2^32-1 bytes) */
#define PK_ENC          "PK"
#define CP_ABE          "CP"
#define KP_ABE          "KP"

#define MPK_ID          "mpk"
#define MSK_ID          "msk"
#define SK_ID           "decKey"

#define MPK_FILENAME	"mpk.cpabe"
#define MSK_FILENAME	"msk.cpabe"
#define NAME_SEP        '.'
#define KEY_SUFFIX      ".key"

#define BLOCK	"BLOCK"
/* encloses mpk */
#define NL		"\n"

#define MPK_BEGIN_HEADER	"-----BEGIN MASTER PUBLIC KEY BLOCK-----\n"
#define MPK_END_HEADER		"\n-----END MASTER PUBLIC KEY BLOCK-----\n"
/* encloses msk */
#define MSK_BEGIN_HEADER	"-----BEGIN MASTER SECRET KEY BLOCK-----\n"
#define MSK_END_HEADER		"\n-----END MASTER SECRET KEY BLOCK-----\n"
/* encloses pk */
#define PK_BEGIN_HEADER     "-----BEGIN USER PUBLIC KEY BLOCK-----\n"
#define PK_END_HEADER       "\n-----END USER PUBLIC KEY BLOCK-----\n"
/* encloses sk */
#define SK_BEGIN_HEADER		"-----BEGIN USER PRIVATE KEY BLOCK-----\n"
#define SK_END_HEADER		"\n-----END USER PRIVATE KEY BLOCK-----\n"
/* encloses the abe ciphertext */
#define CT1_BEGIN_HEADER	"-----BEGIN ABE CIPHERTEXT BLOCK-----"
#define CT1_END_HEADER		"-----END ABE CIPHERTEXT BLOCK-----"
/* encloses the ciphertext for symmetric key encryption portion */
#define CT2_BEGIN_HEADER	"-----BEGIN CIPHERTEXT BLOCK-----"
#define CT2_END_HEADER		"-----END CIPHERTEXT BLOCK-----"

void getFile(std::string &result, const std::string &filename);
std::string ReadFile(const char* filename);
std::string ReadBlockFromFile(const char* begin_header, const char* end_header, const char* filename);
std::string ReadBinaryFile(const char* filename);
void WriteToFile(const char* filename, std::string outputStr);
void WriteBinaryFile(const char* filename, std::string& outputStr);
void WriteBinaryFile(const char* filename, uint8_t *buf, uint32_t len);

OpenABE_SCHEME checkForScheme(std::string type, std::string &suffix);
void addNameSeparator(std::string &prefix);
void addFileExtension(std::string &filename, std::string ext);

#endif /* common header */
