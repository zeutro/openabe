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
/// \file   zkeystore.h
///
/// \brief  Class definition for the OpenABE keystore.
///
/// \author J. Ayo Akinyele
///

#ifndef __ZKEYMGR_H__
#define __ZKEYMGR_H__

#include <map>
#include <vector>
#include <mutex>

namespace oabe {

struct _OpenABEMetadata {
    /* add as many fields as necessary */
    std::string userId;
    bool isCached, isExpired;
    /* include creationDate, expirationDate, */
    /* attribute list or policy string */
    OpenABEFunctionInputType inputType;
    std::unique_ptr<OpenABEFunctionInput> input;
    OpenABE_SCHEME schemeID;
    OpenABECurveID curveID;
    OpenABEByteString keyBlob;
    uint64_t keyExpirationDate;
};

#define MAX_KEYS_PER_USER  20
typedef std::shared_ptr<_OpenABEMetadata> OpenABEMetadata;

struct OpenABEKeyQuery {
    bool isEfficient, frequentlyAccessed;
    uint64_t currentTime;
    std::string userId;
    /* add other search query ideas here --
     * advanced --> find key for subset of ciphertexts */
};

/// \class  ZKeystoreManager
/// \brief  Keystore Manager class for OpenABEKeys. Stores keys and metadata
///         about the key

class OpenABEKeystoreManager : OpenABEKeystore {
public:
    OpenABEKeystoreManager();
    ~OpenABEKeystoreManager();

    std::pair<std::string,oabe::OpenABEByteString> getKeyCommand(const std::string& userId, const std::string& keyID);
    bool storeWithKeyIDCommand(const std::string& userId, const std::string keyID,
                               OpenABEByteString& keyBlob, uint64_t keyExpireDate,
                               bool canCacheKey = false);
    const std::string storeWithKeyPrefixCommand(const std::string& userId, const std::string keyPrefix,
                                                OpenABEByteString& keyBlob, uint64_t keyExpireDate,
                                                bool canCacheKey = false);

    // tries to find a decryption key that can decrypt one ciphertext
    const std::string searchKeyCommand(OpenABEKeyQuery* query, OpenABEFunctionInput *func_input);
    // deletes keys that satisfy the query (excludes efficiency check though)
    std::vector<std::string> deleteKeyCommand(OpenABEKeyQuery* query);

    // set the passphrase (used to encrypt DB on disk)
    void setPassphrase(const std::string& programId, const std::string& userId, const std::string& passphrase);
    // get active user map
    std::map<std::string,std::string> getActiveUsers();
    int getUserKeyCount(const std::string& userId);

protected:
    std::vector<std::string> filterKeys(const std::string& userId, OpenABEFunctionInputType type);
    std::vector<std::string> getKeyIds(const std::string& userId, uint64_t currentTime = 0);
    void rankKeyAlgorithm(std::vector<std::string>& keyIDs, OpenABEKeyQuery* query);
    std::pair<bool,int> testAKey(OpenABEMetadata& key, OpenABEFunctionInput* funcInput);
    std::mutex ks_lock_;
    const std::string searchKey(OpenABEKeyQuery* query, OpenABEFunctionInput *funcInput);
    std::map<std::string, OpenABEMetadata> keyMetadata_;
    std::map<std::string, unsigned int> keyCounter_;
    std::map<std::string, std::string> keyPassphrase_, activeUsers_;
    std::map<std::string, bool> keyLoaded_;
};

std::unique_ptr<OpenABEFunctionInput> getFunctionInput(OpenABEKey *key);
OpenABEFunctionInputType getFunctionInputType(OpenABEKey *key);

}

#endif // __ZKEYMGR_H__
