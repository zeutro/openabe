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
/// \file   zcontextkpgpsw.cpp
///
/// \brief  Implementation of the KP-ABE [GPSW '06] scheme.
///
/// \source [GPSW 06, Sec 5] and [PTMW 06, Sec 2.2 + Appendix B]
///
/// \author J. Ayo Akinyele
///

#define __ZCONTEXTKPGPSW_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>

#include <openabe/openabe.h>
#include <openabe/utils/zcryptoutils.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEContextKPGPSW class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEContextKPGPSW class.
 *
 */

OpenABEContextKPGPSW::OpenABEContextKPGPSW(unique_ptr<OpenABERNG> rng) : OpenABEContextABE() {
  this->debug = false;
  this->m_RNG_ = move(rng);
  this->algID = OpenABE_SCHEME_KP_GPSW;
}

/*!
 * Destructor for the OpenABEContextKPGPSW class.
 *
 */

OpenABEContextKPGPSW::~OpenABEContextKPGPSW() {}

/*!
 * Generate scheme public and private parameters for the Waters '11 CP-ABE
 * scheme. This function takes in a specific set of pairing parameters.
 *
 * @param[in] pairingParams     - Identifier for the pairing parameters.
 * @param[in] mpkID             - Identifier to use for the new Master Public Key
 * @param[in] mskID             - Identifier to use for the new Master Secret Key
 * @return                      - An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextKPGPSW::generateParams(const string pairingParams,
                                 const string &mpkID, const string &mskID) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEKey> MPK = nullptr, MSK = nullptr;
  OpenABERNG *myRNG = this->getRNG();
  OpenABEByteString k;

  try {
    // Instantiate a OpenABE pairing object with the given parameters
    this->initializeCurve(pairingParams);

    // Make sure these parameter IDs are valid and not already in use
    if (this->getKeystore()->validateNewParamsID(mpkID) == false ||
        this->getKeystore()->validateNewParamsID(mskID) == false) {
      throw OpenABE_ERROR_INVALID_PARAMS_ID;
    }

    // Initialize the elements of the public and secret parameters
    MPK.reset(new OpenABEKey(this->getPairing()->getCurveID(), this->algID, mpkID));
    MSK.reset(new OpenABEKey(this->getPairing()->getCurveID(), this->algID, mskID));

    // Select random generators g1 \in G1 and g2 \in G2
    G1 g1 = this->getPairing()->randomG1(myRNG);
    G2 g2 = this->getPairing()->randomG2(myRNG);
    // Select random y \in ZP
    ZP y = this->getPairing()->randomZP(myRNG);
    // Compute e(g,g2) ==> e(g1,g2)^y
    GT Y = this->getPairing()->pairing(g1, g2).exp(y);
    // key prefix for hash function
    myRNG->getRandomBytes(&k, HASH_LEN);

    // MPK = {g1, g2, Y = e(g1, g2)^y, k}
    MPK->setComponent("g1", &g1);
    MPK->setComponent("g2", &g2);
    MPK->setComponent("Y", &Y);
    MPK->setComponent("k", &k);
    // MSK = {y}
    MSK->setComponent("y", &y);

    // Add (MPK, MSK) to the keystore
    this->getKeystore()->addKey(mpkID, MPK, KEY_TYPE_PUBLIC);
    this->getKeystore()->addKey(mskID, MSK, KEY_TYPE_SECRET);

  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}


/*!
 * Generate a decryption key for a given function input. This function
 * requires that the master secret parameters are available.
 *
 * @param[in] mpkID     - parameter ID of the Master Public Key
 * @param[in] mskID     - parameter ID of the Master Secret Key
 * @param[in] keyID     - parameter ID of the decryption key to be created
 * @param[in] keyInput  - A OpenABEPolicy structure for the key to be constructed
 * @return              - An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextKPGPSW::generateDecryptionKey(
    OpenABEFunctionInput *keyInput, const string &keyID, const string &mpkID,
    const string &mskID, const string &gpkID = "", const string &GID = "") {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEKey> decKey = nullptr;
  OpenABEPolicy *policy = nullptr;
  OpenABERNG *myRNG = this->getRNG();
  OpenABEByteString *k = nullptr;

  try {
    // Ensure that the given input is a OpenABEPolicy
    if ((policy = dynamic_cast<OpenABEPolicy *>(keyInput)) == nullptr) {
      OpenABE_LOG_AND_THROW("Encryption input must be a Policy",
                        OpenABE_ERROR_INVALID_INPUT);
    }

    // Load the master secret and public key
    shared_ptr<OpenABEKey> MPK = this->getKeystore()->getPublicKey(mpkID);
    shared_ptr<OpenABEKey> MSK = this->getKeystore()->getSecretKey(mskID);
    if (MPK == nullptr || MSK == nullptr) {
      throw OpenABE_ERROR_INVALID_PARAMS;
    }
    // retrieve the hash function key prefix
    k = MPK->getByteString("k");

    // Create a new OpenABEKey object for the decryption key
    decKey.reset(
        new OpenABEKey(this->getPairing()->getCurveID(), this->algID, keyID));

    // Store the policy in the decryption key
    OpenABEByteString pol;
    pol = policy->toCompactString();
    decKey->setComponent("input", &pol);
    ZP y = *(MSK->getZP("y"));

    OpenABELSSS lsss(this->getPairing(), myRNG);
    // Share the secret y over the policy tree
    lsss.shareSecret(policy, y);

    // For each element/share of the policy tree
    string attr_deckey;
    OpenABELSSSRowMap lsssRows = lsss.getRows();
    for (auto it = lsssRows.begin(); it != lsssRows.end(); ++it) {
      // Pick a random value ri in ZP
      ZP ri = this->getPairing()->randomZP(myRNG);
      // Di = g ^ \share(attr) * H(attr)^ri
      G1 Di = MPK->getG1("g1")->exp(it->second.element()) *
              this->getPairing()->hashToG1(*k, it->second.label()).exp(ri);
      // di = g ^ ri
      G2 di = MPK->getG2("g2")->exp(ri);
      attr_deckey = OpenABEHashKey(it->first);
      decKey->setComponent(OpenABEMakeElementLabel("D", attr_deckey), &Di);
      decKey->setComponent(OpenABEMakeElementLabel("d", attr_deckey), &di);
    }

    // Add the decryption key to the keystore
    this->getKeystore()->addKey(keyID, decKey, KEY_TYPE_SECRET);
  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

/*!
 * Generate and encrypt a symmetric key using the key encapsulation mode
 * of the scheme. Return the key and ciphertext.
 *
 * @param   Parameters ID for the public master parameters.
 * @param   Function input for the encryption: OpenABEAttributeList
 * @return  An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextKPGPSW::encryptKEM(OpenABERNG *rng, const string &mpkID,
                             const OpenABEFunctionInput *encryptInput,
                             uint32_t keyByteLen,
                             const std::shared_ptr<OpenABESymKey> &key,
                             OpenABECiphertext *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABERNG *myRNG = this->getRNG();
  shared_ptr<OpenABEKey> MPK = nullptr;
  OpenABEByteString *k = nullptr;

  try {
    ASSERT_NOTNULL(key);
    ASSERT_NOTNULL(ciphertext);
    if (rng != nullptr) {
      // Use the provided RNG
      myRNG = rng;
    }
    // Assert that the RNG has been set
    ASSERT_NOTNULL(myRNG);

    // Ensure that the given input is a OpenABEAttributeList
    const OpenABEAttributeList *attrList =
        dynamic_cast<const OpenABEAttributeList *>(encryptInput);
    if (attrList == nullptr) {
      OpenABE_LOG_AND_THROW("Encryption input must be a Policy",
                        OpenABE_ERROR_INVALID_INPUT);
    }
    // Load the master public key
    if ((MPK = this->getKeystore()->getPublicKey(mpkID)) == nullptr) {
      OpenABE_LOG_AND_THROW("Could not get master public params",
                        OpenABE_ERROR_INVALID_PARAMS);
    }
    // Retrieve the hash function key prefix
    k = MPK->getByteString("k");
    // Choose random t \in ZP
    ZP t = this->getPairing()->randomZP(myRNG);
    // Compute Y^t => e(g1, g2)^(y*t). Note: this is hashed into a key later due
    // to KEM
    GT Cpr1 = MPK->getGT("Y")->exp(t);
    // Compute g2 ^ t
    G2 Cpr2 = MPK->getG2("g2")->exp(t);
    ciphertext->setComponent("Cpr2", &Cpr2);

    string attr, attr_key;
    const vector<string> *attrStrings = attrList->getAttributeList();
    for (auto it = attrStrings->begin(); it != attrStrings->end(); ++it) {
      // For each attribute in input, compute H(attribute) ^ t
      attr = *it;
      G1 hG1 = this->getPairing()->hashToG1(*k, attr).exp(t);
      attr_key = OpenABEHashKey(attr);
      ciphertext->setComponent(OpenABEMakeElementLabel("C", attr_key), &hG1);
    }
    // Set the attribute list in the policy
    ciphertext->setComponent("attributes", attrList);

    // Hash Cpr1 to obtain the encapsulation key.
    key->hashToSymmetricKey(Cpr1, keyByteLen, HASH_FUNCTION_TYPE_SHA256);
    // Set the ciphertext header
    ciphertext->setHeader(this->getPairing()->getCurveID(), this->algID, myRNG);

  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

/*!
 * Decrypt a symmetric key using the key encapsulation mode
 * of the scheme. Return the key.
 *
 * @param   Parameters ID for the public master parameters.
 * @param   Identifier for the decryption key to be used.
 * @param   ABE ciphertext.
 * @param   Symmetric key to be returned.
 * @return  An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextKPGPSW::decryptKEM(const string &mpkID, const string &keyID,
                             OpenABECiphertext *ciphertext, uint32_t keyByteLen,
                             const std::shared_ptr<OpenABESymKey> &key) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABERNG *myRNG = this->getRNG();

  try {
    ASSERT_NOTNULL(ciphertext);
    ASSERT_NOTNULL(key);
    // Load the given decryption key
    shared_ptr<OpenABEKey> decKey = this->getKeystore()->getSecretKey(keyID);
    ASSERT_NOTNULL(decKey);

    // Obtain the attribute list from the decryption key
    OpenABEByteString *policy_str = decKey->getByteString("input");
    ASSERT_NOTNULL(policy_str);
    unique_ptr<OpenABEPolicy> policy = createPolicyTree(policy_str->toString());

    // Obtain the attribute list from the decryption key
    OpenABEAttributeList *attrList =
        (OpenABEAttributeList *)ciphertext->getComponent("attributes");
    ASSERT_NOTNULL(attrList);

    // Initialize an LSSS structure. Given an attribute list and policy
    // it will identify the necessary solution and return the appropriate
    // components of the access/policy and secret key along with coefficients.
    // If the policy is not satisfied, it throws an error.
    OpenABELSSS lsss(this->getPairing(), myRNG);
    lsss.recoverCoefficients(policy.get(), attrList);

    ZP coeff;
    G1 prod1 = this->getPairing()->initG1();
    G1 *Ci, *Di;
    G2 *di;
    GT prodT = this->getPairing()->initGT();
    vector<G1> g1s;
    vector<G2> g2s;
    // Get coefficients for satisfiable attributes
    OpenABELSSSRowMap lsssRows = lsss.getRows();
    string attr_key, attr_deckey;
    for (auto it = lsssRows.begin(); it != lsssRows.end(); ++it) {
      coeff = it->second.element();
      attr_key = OpenABEHashKey(it->second.label());
      Ci = ciphertext->getG1(OpenABEMakeElementLabel("C", attr_key));
      attr_deckey = OpenABEHashKey(it->first);

      di = decKey->getG2(OpenABEMakeElementLabel("d", attr_deckey));
      // prod1 => prod{i \in S} D_i ^ coeff_i
      Di = decKey->getG1(OpenABEMakeElementLabel("D", attr_deckey));
      prod1 *= Di->exp(coeff);
      // prodT => prod{i \in S} e(d_i, C_i)
      g1s.push_back(Ci->exp(coeff));
      g2s.push_back(*di);
    }
    // prodT => prod{i \in S} e(d_i, C_i)
    this->getPairing()->multi_pairing(prodT, g1s, g2s);
    G2 *Cpr2 = ciphertext->getG2("Cpr2");
    ASSERT_NOTNULL(Cpr2);
    GT A = this->getPairing()->pairing(prod1, *Cpr2) / prodT;

    // Compute key = hash_to_bitstring( A );
    key->hashToSymmetricKey(A, keyByteLen, HASH_FUNCTION_TYPE_SHA256);

  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

}
