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
/// \file   zcrypto_box.h
///
/// \brief  Thin context wrappers for PKE/PKSIG/ABE (without any advanced features)
///
/// \author J. Ayo Akinyele
///

#ifndef __ZCRYPTO_BOX__
#define __ZCRYPTO_BOX__

#include <memory>
#include <openabe/utils/zexception.h>

namespace oabe {

typedef std::unique_ptr<crypto::OpenABESymKeyHandle> OpenABESymKeyHandlePtr;

class OpenABECryptoContextBase {
public:
  // generate system parameters for default curve selected.
  virtual void generateParams() = 0;
  virtual void enableKeyManager(const std::string userId) = 0;

  // for CP/KP-ABE
  virtual void exportPublicParams(std::string &mpk) = 0;
  virtual void exportSecretParams(std::string &msk) = 0;
  virtual void importPublicParams(const std::string &keyBlob) = 0;
  virtual void importSecretParams(const std::string &keyBlob) = 0;

  // for multi-authority (allow import per authID)
  virtual void importPublicParams(const std::string &authID,
                        const std::string &keyBlob) = 0;

  virtual void importSecretParams(const std::string &authID,
                        const std::string &keyBlob) = 0;
  virtual void importUserKey(const std::string &keyID,
                             const std::string &keyBlob) = 0;

  virtual void exportUserKey(const std::string &keyID,
                             std::string &keyBlob) = 0;
  virtual bool deleteKey(const std::string &keyID) = 0;
};

/*!
 * A crypto_box interface for attribute-based encryption.
 * Scheme-ID options: "CP-ABE", "KP-ABE", and "MA-ABE".
 * Note: This context is CCA-secure by default
 * Example usage:
 *   OpenABECryptoContext cpabe("CP-ABE");
 *   cpabe.generateParams();
 *   cpabe.keygen("attr1|attr2", "key0");
 *   string ct, pt1 = "message", pt2;
 *   cpabe.encrypt("attr1 and attr2", pt1, ct);
 *   bool res = cpabe.decrypt("key0", ct, pt2);
 *   assert(res && pt1 == pt2);
 */
class OpenABECryptoContext : public OpenABECryptoContextBase {
public:
  OpenABECryptoContext(const std::string scheme_id, bool base64encode = true);
  virtual ~OpenABECryptoContext() {};
  // generate system parameters for default curve selected.
  void generateParams();
  void enableKeyManager(const std::string userId);
  void enableVerbose();

  // import/export various params and keys (for multi-authority)
  void exportGlobalParams(std::string &globlmpk);
  void importGlobalParams(const std::string &keyBlob);

  // for CP/KP-ABE
  void exportPublicParams(std::string &mpk);
  void exportSecretParams(std::string &msk);
  void importPublicParams(const std::string &keyBlob);
  void importSecretParams(const std::string &keyBlob);

  // for multi-authority (allow import per authID)
  void importPublicParams(const std::string &authID,
                          const std::string &keyBlob);

  void importSecretParams(const std::string &authID,
                          const std::string &keyBlob);
  void importUserKey(const std::string &keyID, const std::string &keyBlob);
  void exportUserKey(const std::string &keyID, std::string &keyBlob);
  bool deleteKey(const std::string &keyID);

  void keygen(const std::string &keyInput, const std::string &keyID,
              const std::string &authID = "", const std::string &GID = "");
  void encrypt(const std::string encInput, const std::string &plaintext,
               std::string &ciphertext);
  bool decrypt(const std::string &keyID, const std::string &ciphertext,
               std::string &plaintext);
  bool decrypt(const std::string &ciphertext, std::string &plaintext);

private:
  std::string userId_;
  std::unique_ptr<OpenABEContextSchemeCCA> schemeContextCCA_;
  std::unique_ptr<OpenABEKeystoreManager> keyManager_;
  OpenABE_SCHEME scheme_type_;
  OpenABEFunctionInputType keyInputType_, encInputType_;
  bool base64Encode_, debug_, useKeyManager_;
};

/*!
 * A crypto_box interface for public-key encryption
 * (i.e., One-pass DH in Sec 6.2.2.2 of NIST SP800-56A)
 * Example usage:
 *   OpenPKEContext pke;
 *   pke.keygen("user0");
 *   string pt = "message", ct;
 *   pke.encrypt("user0", pt1, ct);
 *   bool res = pke.decrypt("user0", ct, pt2);
 *   assert(res && pt1 == pt2);
 */
class OpenPKEContext {
public:
  OpenPKEContext(const std::string ec_id = "NIST_P256", bool base64encode = true);
  virtual ~OpenPKEContext() {};

  void exportPublicKey(const std::string key_id, std::string &keyBlob);
  void exportPrivateKey(const std::string key_id, std::string &keyBlob);

  void importPublicKey(const std::string key_id, const std::string &keyBlob);
  void importPrivateKey(const std::string key_id, const std::string &keyBlob);

  void keygen(const std::string key_id);
  bool encrypt(const std::string receiver_id, const std::string &plaintext,
               std::string &ciphertext);
  bool decrypt(const std::string receiver_id, const std::string &ciphertext,
               std::string &plaintext);

private:
  std::unique_ptr<OpenABEContextSchemePKE> schemeContext_;
  std::string ec_id_;
  bool base64Encode_;
};

/*!
 * A crypto_box interface for digital signatures (e.g., NIST EC-DSA)
 * Example usage:
 *   OpenPKSIGContext pksig;
 *   pksig.keygen("user1");
 *   pksig.sign("user1", msg, sig);
 *   bool res = pksig.verify("user1", msg, sig);
 *   assert(res);
 */
class OpenPKSIGContext {
public:
  OpenPKSIGContext(const std::string ec_id = "NIST_P256", bool base64encode = true);
  virtual ~OpenPKSIGContext() {};

  void exportPublicKey(const std::string key_id, std::string &keyBlob);
  void exportPrivateKey(const std::string key_id, std::string &keyBlob);

  void importPublicKey(const std::string key_id, const std::string &keyBlob);
  void importPrivateKey(const std::string key_id, const std::string &keyBlob);

  void keygen(const std::string key_id);
  void sign(const std::string key_id, const std::string &message,
            std::string &signature);
  bool verify(const std::string key_id, const std::string &message,
              const std::string &signature);

private:
  std::unique_ptr<OpenABEContextSchemePKSIG> schemeContext_;
  std::string ec_id_;
  bool base64Encode_;
};


// helper methods to help with using the keystore
//std::pair<std::string,std::string> SearchKeyStore(OpenABEKeystoreManager& key_manager, std::string& id, std::string& ciphertext);

}

#endif // __ZCRYPTO_BOX__

