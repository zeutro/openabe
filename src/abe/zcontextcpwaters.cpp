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
/// \file   zcontextcpwaters.cpp
///
/// \brief  Implementation of the Waters '11 CP-ABE scheme.
///
/// \source http://eprint.iacr.org/2008/290.pdf (Appendix A -- Large Universe Construction)
///
/// \author J. Ayo Akinyele
///

#define __ZCONTEXTCPWATERS_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>
#include <openabe/utils/zcryptoutils.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEContextCPWaters class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEContextCPWaters class.
 *
 */
OpenABEContextCPWaters::OpenABEContextCPWaters(unique_ptr<OpenABERNG> rng)
    : OpenABEContextABE() {
  this->debug = false;
  // KEM context will take ownership of the given RNG
  this->m_RNG_ = move(rng);
  this->algID = OpenABE_SCHEME_CP_WATERS;
}

/*!
 * Destructor for the OpenABEContextCPWaters class.
 *
 */
OpenABEContextCPWaters::~OpenABEContextCPWaters() {}

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
OpenABEContextCPWaters::generateParams(const string pairingParams,
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

    // Select random generators g1 \in G1, g2 \in G2
    G1 g1 = this->getPairing()->randomG1(myRNG);
    G2 g2 = this->getPairing()->randomG2(myRNG);
    // Select two random elements (a, \alpha) \in ZP
    ZP alpha = this->getPairing()->randomZP(myRNG);
    ZP a = this->getPairing()->randomZP(myRNG);
    // key prefix for hash function
    myRNG->getRandomBytes(&k, HASH_LEN);

    // Compute g1^a, g2^a
    G1 g1a = g1.exp(a);
    G2 g2a = g2.exp(a);

    // Compute A = e(g1, g2)^\alpha
    GT A = this->getPairing()->pairing(g1, g2).exp(alpha);

    // Add (g1, g2, g1a) to the public params
    MPK->setComponent("g1", &g1);
    MPK->setComponent("g2", &g2);
    MPK->setComponent("g1a", &g1a);
    MPK->setComponent("A", &A);
    MPK->setComponent("k", &k);

    // Add (\alpha and g2a) to the secret params
    MSK->setComponent("alpha", &alpha);
    MSK->setComponent("g2a", &g2a);

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
 * @param[in] keyInput  - A OpenABEAttributeList structure for the key to be constructed
 * @return              - An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextCPWaters::generateDecryptionKey(
    OpenABEFunctionInput *keyInput, const string &keyID, const string &mpkID,
    const string &mskID, const string &gpkID = "", const string &GID = "") {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEKey> decKey = nullptr;
  OpenABEAttributeList *attrList = nullptr;
  OpenABERNG *myRNG = this->getRNG();
  OpenABEByteString *k = nullptr;

  try {
    // Ensure that the given input is a OpenABEAttributeList
    if ((attrList = dynamic_cast<OpenABEAttributeList *>(keyInput)) == nullptr) {
      OpenABE_LOG_AND_THROW("Decryption key input must be an Attribute List",
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

    // Add the attribute list to the key
    decKey->setComponent("input", attrList);

    // Select a random element t \in ZP
    ZP t = this->getPairing()->randomZP(myRNG);
    ZP alpha = *(MSK->getZP("alpha"));

    // K = g2^\alpha * (g2^{a})^t
    G2 K = (MPK->getG2("g2")->exp(alpha)) * (MSK->getG2("g2a")->exp(t));
    decKey->setComponent("K", &K);

    // L = g2^t
    G2 L = MPK->getG2("g2")->exp(t);
    decKey->setComponent("L", &L);

    // For each attribute in the attribute list
    string attr, attr_deckey;
    const vector<string> *attrStrings = attrList->getAttributeList();
    for (auto it = attrStrings->begin(); it != attrStrings->end(); ++it) {
      // Compute KX_{attribute} = hash_to_G1(attribute)^t
      attr = *it;
      G1 kx = this->getPairing()->hashToG1(*k, attr).exp(t);
      attr_deckey = OpenABEHashKey(attr);
      decKey->setComponent(OpenABEMakeElementLabel("KX", attr_deckey), &kx);
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
 * @param   Function input for the encryption.
 * @return  An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextCPWaters::encryptKEM(OpenABERNG *rng, const string &mpkID,
                               const OpenABEFunctionInput *encryptInput,
                               uint32_t keyByteLen,
                               const std::shared_ptr<OpenABESymKey> &key,
                               OpenABECiphertext *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABERNG *myRNG = this->getRNG();
  OpenABEByteString *k = nullptr;

  try {
    ASSERT_NOTNULL(key);
    ASSERT_NOTNULL(ciphertext);

    if (rng != nullptr) {
      // use the passed in RNG
      myRNG = rng;
    }
    // Assert that the RNG has been set
    ASSERT_NOTNULL(myRNG);

    // Ensure that the given input is a OpenABEPolicy
    const OpenABEPolicy *policy = dynamic_cast<const OpenABEPolicy *>(encryptInput);
    if (policy == nullptr) {
      OpenABE_LOG_AND_THROW("Encryption input must be a Policy",
                        OpenABE_ERROR_INVALID_INPUT);
    }
    // Load the master public key
    shared_ptr<OpenABEKey> MPK = this->getKeystore()->getPublicKey(mpkID);
    if (MPK == nullptr) {
      throw OpenABE_ERROR_INVALID_PARAMS;
    }
    // retrieve the hash function key prefix
    k = MPK->getByteString("k");

    // Select s and compute C = e(g1, g2)^\(alpha*s)
    ZP s = this->getPairing()->randomZP(myRNG);
    GT C = MPK->getGT("A")->exp(s);

    // Use the Linear Secret Sharing Scheme (LSSS) to compute an enumerated list
    // of all
    // attributes and corresponding secret shares of s.
    OpenABELSSS lsss(this->getPairing(), myRNG);
    lsss.shareSecret(policy, s);

    // Allocate the ciphertext object and add the policy and key length
    OpenABEByteString pol;
    pol = policy->toCompactString();
    ciphertext->setComponent("policy", &pol);

    // Compute Cprime = g1^s
    G1 Cprime = MPK->getG1("g1")->exp(s);
    ciphertext->setComponent("Cprime", &Cprime);

    // For each element of the LSSS
    ZP ri;
    string attr_key;
    OpenABELSSSRowMap lsssRows = lsss.getRows();
    for (auto it = lsssRows.begin(); it != lsssRows.end(); ++it) {
      // Pick a random value ri.
      ri = this->getPairing()->randomZP(myRNG);
      // Compute D[i] = g2^{ri}
      G2 Di = (MPK->getG2("g2")->exp(ri));
      attr_key = OpenABEHashKey(it->first);
      ciphertext->setComponent(OpenABEMakeElementLabel("D", attr_key), &Di);

      // Compute C[i] = g1a^{share_i} * hash_to_G1(attribute)^{-r}
      G1 hG1 = this->getPairing()->hashToG1(*k, it->second.label());
      G1 Ci = MPK->getG1("g1a")->exp(it->second.element()) * (hG1.exp(-ri));
      ciphertext->setComponent(OpenABEMakeElementLabel("C", attr_key), &Ci);
    }

    // Hash C to obtain the symmetric key result.
    key->hashToSymmetricKey(C, keyByteLen, HASH_FUNCTION_TYPE_SHA256);
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
OpenABEContextCPWaters::decryptKEM(const string &mpkID, const string &keyID,
                               OpenABECiphertext *ciphertext, uint32_t keyByteLen,
                               const std::shared_ptr<OpenABESymKey> &key) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  ZP coeff;
  G1 prod1 = this->getPairing()->initG1();
  G1 *Kx, *Cx;
  G2 *Dx;
  GT prodT = this->getPairing()->initGT();

  try {
    ASSERT_NOTNULL(ciphertext);
    ASSERT_NOTNULL(key);
    // Load the given decryption key
    shared_ptr<OpenABEKey> decKey = this->getKeystore()->getSecretKey(keyID);
    ASSERT_NOTNULL(decKey);
    // Obtain the attribute list from the decryption key
    OpenABEAttributeList *attrList =
        (OpenABEAttributeList *)decKey->getComponent("input");

    // Initialize an LSSS structure. Given an attribute list and policy
    // it will identify the necessary solution and return the appropriate
    // components of the access/policy and secret key along with coefficients.
    // If the policy is not satisfied, it throws an error.
    OpenABELSSS lsss(this->getPairing(), this->getRNG());

    OpenABEByteString *policy_str = ciphertext->getByteString("policy");
    ASSERT_NOTNULL(policy_str);

    unique_ptr<OpenABEPolicy> policy = createPolicyTree(policy_str->toString());
    lsss.recoverCoefficients(policy.get(), attrList);

    // Compute prod1  = prod_{attr_i \in S} C[attr_i]^{coefficient[attr_i]}
    //         prodT = prod_{attr_i \in S} e(KX[attr_i]^{coefficient[attr_i]},
    //         D[attr_i])
    vector<G1> g1s;
    vector<G2> g2s;
    string attr_key, attr_deckey;
    OpenABELSSSRowMap lsssRows = lsss.getRows();
    for (auto it = lsssRows.begin(); it != lsssRows.end(); ++it) {
      coeff = it->second.element();
      attr_key = OpenABEHashKey(it->first);
      attr_deckey = OpenABEHashKey(it->second.label());
      Kx = decKey->getG1(OpenABEMakeElementLabel("KX", attr_deckey));
      Cx = ciphertext->getG1(OpenABEMakeElementLabel("C", attr_key));
      ASSERT_NOTNULL(Cx);
      Dx = ciphertext->getG2(OpenABEMakeElementLabel("D", attr_key));
      ASSERT_NOTNULL(Dx);
      prod1 *= (Cx->exp(coeff));
      // G1 Kxpr = Kx->exp(coeff);
      // prodT *= this->getPairing()->pairing(Kxpr,  *Dx);
      g1s.push_back(Kx->exp(coeff));
      g2s.push_back(*Dx);
    }

    this->getPairing()->multi_pairing(prodT, g1s, g2s);
    G1 *Cprime = ciphertext->getG1("Cprime");
    G2 *K = decKey->getG2("K");
    G2 *L = decKey->getG2("L");
    ASSERT_NOTNULL(Cprime);
    ASSERT_NOTNULL(K);
    ASSERT_NOTNULL(L);
    // Now compute final = e(Cprime, K) / (prodT * e(prod1, L))
    GT final = this->getPairing()->pairing(*Cprime, *K) /
               (prodT * this->getPairing()->pairing(prod1, *L));
    // Compute key = hash_to_bitstring( prodT );
    key->hashToSymmetricKey(final, keyByteLen, HASH_FUNCTION_TYPE_SHA256);
  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

}
