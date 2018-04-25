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
/// \file   zkeymgr.cpp
///
/// \brief  Class implementation for the OpenABE keystore manager (keystore patent).
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <string>
#include <assert.h>
#include <openabe/openabe.h>

using namespace std;

namespace oabe {

/********************************************************************************
 * Implementation of the OpenABEKeystoreManager class
 ********************************************************************************/

OpenABEKeystoreManager::OpenABEKeystoreManager(): OpenABEKeystore() {
}

OpenABEKeystoreManager::~OpenABEKeystoreManager() {
    // clear out metadata structure
    keyPassphrase_.clear();
}

void
OpenABEKeystoreManager::setPassphrase(const std::string& programId, const std::string& userId, const std::string& passphrase) {
    keyPassphrase_[userId] = passphrase;
    activeUsers_[userId] = programId;
}

map<string,string>
OpenABEKeystoreManager::getActiveUsers() {
    return activeUsers_;
}

bool
OpenABEKeystoreManager::storeWithKeyIDCommand(const string& userId, const std::string keyID,
                                          OpenABEByteString& keyBlob, uint64_t keyExpireDate,
                                          bool canCacheKey) {
    OpenABEMetadata metadata(new _OpenABEMetadata);
    OpenABEByteString origBlob = keyBlob, outputKeyBytes;
    // parse the header first
    shared_ptr<OpenABEKey> key = nullptr;
    assert(userId != "");

    if (keyMetadata_.count(keyID) != 0) {
    	keyMetadata_.erase(keyID);
    }

    key = this->parseKeyHeader(keyID, keyBlob, outputKeyBytes);
    if(key == nullptr) {
        THROW_ERROR(OpenABE_ERROR_INVALID_INPUT);
    }

    bool foundAnExistingKey = false;
    string funcInputStr, funcInputStrNew;
    OpenABECurveID curveID = OpenABE_getCurveID(key->getCurveID());
    OpenABE_SCHEME schemeID = OpenABE_getSchemeID(key->getAlgorithmID());
    // create the group object based on curve ID.
    std::shared_ptr<ZGroup> group;
    OpenABE_setGroupObject(group, curveID);

    if(curveID != OpenABE_NONE_ID && schemeID != OpenABE_SCHEME_NONE) {
        // parse the body of the key
        key->setGroup(group);
        key->loadKeyFromBytes(outputKeyBytes);
        // check if input
        unique_ptr<OpenABEFunctionInput> keyInput = getFunctionInput(key.get());
        funcInputStrNew = keyInput->toCompactString();
        // search existing metadata (if available)
        for (auto it = keyMetadata_.begin(); it != keyMetadata_.end(); it++) {
            funcInputStr = it->second->input->toCompactString();
            if (funcInputStr.compare(funcInputStrNew) == 0 // same func input & type
                    && keyInput->getFunctionType() == it->second->input->getFunctionType()
                    && userId.compare(it->second->userId) == 0) {
                foundAnExistingKey = true;
                break;
            }
        }

        if (foundAnExistingKey) {
            // no need to add key
            return false;
        }

        // add info to metadata here
        metadata->userId  = userId;
        metadata->keyBlob = origBlob;
        metadata->keyExpirationDate = keyExpireDate;
        metadata->curveID = curveID;
        metadata->schemeID = schemeID;
        metadata->inputType = keyInput->getFunctionType();
        metadata->input = move(keyInput);
        metadata->isCached = canCacheKey;
        keyMetadata_[keyID] = metadata;
        return true;
    }
    return false;
}

const string
OpenABEKeystoreManager::storeWithKeyPrefixCommand(const string& userId, const string keyPrefix,
                                              OpenABEByteString& keyBlob, uint64_t keyExpireDate,
                                              bool canCacheKey) {
    // choose new key ID based on some user-defined prefix
    std::lock_guard<std::mutex> lock(ks_lock_);

    if(keyCounter_.count(userId) == 0)
        keyCounter_[userId] = 0;
    const string keyID = keyPrefix + to_string(keyCounter_[userId]);
    if (storeWithKeyIDCommand(userId, keyID, keyBlob, keyExpireDate, canCacheKey)) {
        // increment the key counter
        // currentKeyCounter++;
    	int key_count = ((keyCounter_[userId] + 1) % MAX_KEYS_PER_USER);
        keyCounter_[userId] = key_count;
        // return new key ID reference
        return keyID;
    }
    // failed to store key
    return "";
}

int OpenABEKeystoreManager::getUserKeyCount(const std::string& userId) {
    return keyCounter_[userId];
}

pair<string,OpenABEByteString>
OpenABEKeystoreManager::getKeyCommand(const string& userId, const string& keyID) {
    OpenABEByteString keyBlob;
    string funcInput = "";
    std::lock_guard<std::mutex> lock(ks_lock_);

    if(keyMetadata_.count(keyID) != 0) {
        auto& keyMd = keyMetadata_[keyID];
        if (keyMd->userId.compare(userId) == 0) {
            keyBlob = keyMd->keyBlob;
            funcInput = keyMd->input->toCompactString();
        }
    }
    return make_pair(funcInput, keyBlob);
}

vector<string>
OpenABEKeystoreManager::filterKeys(const string& userId, OpenABEFunctionInputType type) {
    vector<string> keyList;
    OpenABEFunctionInputType target_type;
    OpenABEMetadata tmp;
    if (userId == "") {
        /* return an empty key list */
        return keyList;
    }

    /* filter keys based on opposite of 'type' */
    if(type == FUNC_POLICY_INPUT)
        target_type = FUNC_ATTRLIST_INPUT;
    else if(type == FUNC_ATTRLIST_INPUT)
        target_type = FUNC_POLICY_INPUT;
    else
        target_type = FUNC_INVALID_INPUT;

    map<string,OpenABEMetadata>::iterator it;
    for(it = keyMetadata_.begin(); it != keyMetadata_.end(); it++) {
        if (it->second->inputType == target_type) {
            if (userId.compare(it->second->userId) == 0) {
                // if user Id set and matches the Id on the key metadata
                // cout << "Filter keys for: " << currentUserId_ << endl;
                keyList.push_back(it->first);
             }
        }
    }

    return keyList;
}

vector<string>
OpenABEKeystoreManager::getKeyIds(const std::string& userId, uint64_t currentTime) {
    vector<string> keyList;
    OpenABEMetadata tmp;

    map<string,OpenABEMetadata>::iterator it;
    for(it = keyMetadata_.begin(); it != keyMetadata_.end(); it++) {
        if(userId.compare(it->second->userId) == 0) {
            if (currentTime == 0)
               keyList.push_back(it->first);
            else if (currentTime >= it->second->keyExpirationDate)
               keyList.push_back(it->first);
        } else {
            // try to find expired keys (regardless of userId matching)
            if (currentTime > 0 && currentTime >= it->second->keyExpirationDate) {
                keyList.push_back(it->first);
            }
        }
    }
    return keyList;
}

void
OpenABEKeystoreManager::rankKeyAlgorithm(vector<string>& keyIDs, OpenABEKeyQuery* query) {
    /* do nothing for now */
    return;
}

struct key_ref_compare {
    bool operator()(const std::pair<string,int> &left, const std::pair<string,int> &right) {
        return (left.second < right.second);
    }
};

pair<bool,int>
OpenABEKeystoreManager::testAKey(OpenABEMetadata& key, OpenABEFunctionInput* funcInput) {
    OpenABEPolicy *policy = nullptr;
    OpenABEAttributeList *attr_list = nullptr;
    ASSERT_NOTNULL(funcInput);
    if(key->inputType == FUNC_ATTRLIST_INPUT &&
            funcInput->getFunctionType() == FUNC_POLICY_INPUT) {
        policy    = (OpenABEPolicy *) funcInput;
        attr_list = (OpenABEAttributeList *) key->input.get();
    }
    else if(key->inputType == FUNC_POLICY_INPUT &&
            funcInput->getFunctionType() == FUNC_ATTRLIST_INPUT) {
        policy = (OpenABEPolicy *) key->input.get();
        attr_list = (OpenABEAttributeList *) funcInput;
    }
    else {
        /* throw an error - invalid input on either key or ciphertext (most likely ciphertext) */
        throw OpenABE_ERROR_INVALID_CIPHERTEXT_HEADER;
    }
    return checkIfSatisfied(policy, attr_list);
}

const std::string
OpenABEKeystoreManager::searchKeyCommand(OpenABEKeyQuery* query, OpenABEFunctionInput *func_input) {
    // call search key on the functional input
    std::lock_guard<std::mutex> lock(ks_lock_);
    return searchKey(query, func_input);
}

vector<std::string>
OpenABEKeystoreManager::deleteKeyCommand(OpenABEKeyQuery* query) {
    ASSERT_NOTNULL(query);
    vector<std::string> keyList;

    std::lock_guard<std::mutex> lock(ks_lock_);
    keyList = getKeyIds(query->userId, query->currentTime);

    if (query->currentTime > 0) {
        // prune keys based on expiration date and userIds
        if (keyList.size() > 0) cout << "Pruning " << keyList.size() << " expired keys ..." << endl;
    } else if(query->userId != "") {
        // delete user from active user list
        this->activeUsers_.erase(query->userId);
    } else {
       throw runtime_error("OpenABEKeystoreManager::deleteKeyCommand: invalid delete query.");
    }

    for (size_t i = 0; i < keyList.size(); i++) {
        //cout << "Delete key with Id: " << keyList[i] << " for " << query->userId << endl;
        this->deleteKey(keyList[i]);
    }
    return keyList;
}

const string
OpenABEKeystoreManager::searchKey(OpenABEKeyQuery* query, OpenABEFunctionInput *funcInput) {
    ASSERT_NOTNULL(query);
    ASSERT_NOTNULL(funcInput);
    vector<KeyRef> satKeys;
    // initial set of keys that are available that could satisfy the input ciphertext
    vector<string> keyRefs = filterKeys(query->userId, funcInput->getFunctionType());
    // rank/sort keys based on the contents of the query
    rankKeyAlgorithm(keyRefs, query);
    // test and evaluat each key
    for(size_t i = 0; i < keyRefs.size(); i++) {
        assert(keyMetadata_.count(keyRefs[i]) != 0);
        pair<bool,int> result = testAKey(keyMetadata_[keyRefs[i]], funcInput);
        bool is_satisfied = result.first;
        if (is_satisfied) {
            /* returns the key identifier that satisfies the query */
            if(query->isEfficient) {
                KeyRef p = make_pair(keyRefs[i], result.second);
                satKeys.push_back(p);
            } else {
                // if efficiency is not a concern, then return
                // the first key that would satisfy the func input
                return keyRefs[i];
            }
        }
    }

    // check whether query dictates first satisfied vs. all satisfied
    if(satKeys.size() > 0) {
        std::sort(satKeys.begin(), satKeys.end(), key_ref_compare());
        return satKeys[0].first;
    }
    /* error since no key was found -- indicates that a key request needs to be formed */
    return "";
}

/********************************************************************************
 * OpenABEKeystoreManager utility methods for ciphertexts and keys
 ********************************************************************************/

OpenABEFunctionInputType getFunctionInputType(OpenABEKey *key) {
    OpenABE_SCHEME scheme_type = OpenABE_getSchemeID(key->getAlgorithmID());
    // check the scheme type
    switch(scheme_type) {
        case OpenABE_SCHEME_CP_WATERS:
        case OpenABE_SCHEME_CP_WATERS_CCA:
            return FUNC_ATTRLIST_INPUT;
            break;
        case OpenABE_SCHEME_KP_GPSW:
        case OpenABE_SCHEME_KP_GPSW_CCA:
            return FUNC_POLICY_INPUT;
            break;
        default:
            break;
    }
    return FUNC_INVALID_INPUT;
}

/*
 * NOTE: caller is responsible for deleting memory associated with OpenABEFunctionInput
 */
unique_ptr<OpenABEFunctionInput> getFunctionInput(OpenABEKey *key) {
    OpenABE_SCHEME scheme_type = OpenABE_getSchemeID(key->getAlgorithmID());
    OpenABEByteString *policy_str = NULL;
    OpenABEAttributeList *attrList = NULL;
    unique_ptr<OpenABEPolicy> policy = nullptr;

    // check the scheme type
    switch(scheme_type) {
        case OpenABE_SCHEME_CP_WATERS:
        case OpenABE_SCHEME_CP_WATERS_CCA:
            // attributes are on the key for CP-ABE
            attrList = (OpenABEAttributeList*)key->getComponent("input");
            ASSERT_NOTNULL(attrList);
            return createAttributeList(attrList->toCompactString());
            break;
        case OpenABE_SCHEME_KP_GPSW:
        case OpenABE_SCHEME_KP_GPSW_CCA:
            // policy on the key for KP-ABE
            policy_str = key->getByteString("input");
            ASSERT_NOTNULL(policy_str);
            return createPolicyTree(policy_str->toString());
            break;
        default:
            break;
    }

    return nullptr;
}

}
