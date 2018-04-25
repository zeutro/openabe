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
/// \file   zx509.cpp
///
/// \brief  X.509 certificate handling functionality
///
/// \author Alan Dunn
///

#include <openabe/openabe.h>
#include <openssl/pem.h>
#undef BN_BITS
#undef BN_BYTES
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <assert.h>

using namespace std;
using namespace oabe::crypto;

namespace oabe {

DistinguishedName::DistinguishedName() = default;
DistinguishedName::~DistinguishedName() = default;

class DistinguishedName::Impl {
public:
    Impl(const vector<pair<string,string>>& myRdnPairs)
        : rdnPairs(myRdnPairs) {}

    vector<pair<string,string>> rdnPairs;
};

void DistinguishedName::makeDistinguishedName(
    DistinguishedName& dn,
    const vector<pair<string, string>>& rdnPairs) {
    dn.ptr_.reset(new Impl(rdnPairs));
}

bool KeyCertifier::addDnToX509Name(const DistinguishedName& dn,
                                   X509_NAME* name) {
    int rc;

    if (!name) {
        return false;
    }

    for (auto& rdn : dn.ptr_->rdnPairs) {
        const char* label =
            (char*)rdn.first.c_str();
        const string& value_str = rdn.second;
        const unsigned char* value =
            (unsigned char*)value_str.c_str();
        rc = X509_NAME_add_entry_by_txt(name, label, MBSTRING_ASC,
                                        value, value_str.size(), -1, 0);
        if (rc != 1) {
            return false;
        }
    }

    return true;
}

void KeyCertifier::fromKeyString(KeyCertifier& certifier,
                                 const string& privateKey) {
    stringToPkey(&certifier.privateKey_, privateKey, 1);
    if (!certifier.privateKey_) {
        throw CryptoException("Key misformatted");
    }
}

// OpenSSL finds certificates in chains for verifying based upon
// matching subject DN to issuer DN.  As a result, we need to add a
// distinguished name to the certificates we issue and the CA cert,
// but it doesn't need to signify anything.
static void getBogusDistinguishedName(DistinguishedName& dn) {
    vector<pair<string,string>> rdns;
    rdns.push_back(make_pair("C", "XX"));

    DistinguishedName::makeDistinguishedName(dn, rdns);
}

static bool setCertificateSerialNumber(X509 *cert)
{
    ASN1_INTEGER *sno = ASN1_INTEGER_new();
    BIGNUM *bn = nullptr;
    bool result = false;

    if (!sno) {
        printf("Unable to allocate memory for "
                                           "an ASN1 object");
        goto out;
    }

    bn = BN_new();
    if (!bn) {
        ASN1_INTEGER_free(sno);
        printf("Unable to allocate memory "
                                           "for an BIGNUM object");
        goto out;
    }

    // random for now, but will switch to SHA256(subject, notBefore, notAfter, PK?)
    if (BN_pseudo_rand(bn, SERIAL_BITS, 0, 0) == 1 &&
        (sno = BN_to_ASN1_INTEGER(bn,sno)) != NULL &&
        X509_set_serialNumber(cert, sno) == 1)
        result = true;
    else
        printf("Unable to create or set the serial number");
    if (bn)
        BN_free(bn);
    ASN1_INTEGER_free(sno);
out:
    return result;
}

// OpenSSL checks the validity of certificates based on their period
// of validity.  Thus we need to adjust the period of validity for
// certificates to use them.
static bool setDaysValid(X509* cert,
                         int daysValid) {
    bool result = false;
    const long seconds_in_day = 60*60*24;

    // Backdate the certificate by a day (some period likely long
    // enough to escape synchronization issues) since otherwise lack
    // of timing synchronization between remote server and local
    // server can cause certificate verification to fail (certificate
    // server presents will seem not yet valid).
    if (!X509_gmtime_adj(X509_get_notBefore(cert),
                         (long)-seconds_in_day)) {
        goto out;
    }
    if (!X509_gmtime_adj(X509_get_notAfter(cert),
                         (long)seconds_in_day*daysValid)) {
        goto out;
    }

    result = true;

 out:
    return result;
}

void KeyCertifier::generateCertificate(string& cert,
                                       const string& publicKey,
                                       const string& commonName,
                                       int daysValid) {
    vector<pair<string,string>> subjectRdns;
    subjectRdns.push_back(make_pair("CN", commonName));
    DistinguishedName subjectDn;
    DistinguishedName::makeDistinguishedName(subjectDn, subjectRdns);
    DistinguishedName issuerDn;
    getBogusDistinguishedName(issuerDn);

    generateCertificate(cert,
                        publicKey,
                        issuerDn,
                        subjectDn,
                        daysValid);
}

void KeyCertifier::generateCertificate(string& cert,
                                       const string& publicKey,
                                       const DistinguishedName& issuerDn,
                                       const DistinguishedName& subjectDn,
                                       int daysValid) {
    X509* x509_cert = nullptr;
    X509_NAME* issuer_name, *subject_name;
    EVP_PKEY* pkey = nullptr;
    string error_msg("");
    bool rc;

    stringToPkey(&pkey, publicKey, 0);
    if (!pkey) {
        error_msg = "Key misformatted";
        goto out;
    }

    x509_cert = X509_new();
    if (!x509_cert) {
        error_msg = "X509_new";
        goto out;
    }

    // Set the valid period in the certificate
    if (!setDaysValid(x509_cert, daysValid)) {
        error_msg = "setDaysValid";
        goto out;
    }

    // Add distinguished names to certificate
    issuer_name = X509_get_issuer_name(x509_cert);
    rc = addDnToX509Name(issuerDn, issuer_name);
    if (!rc) {
        error_msg = "addDnToX509Name(issuer)";
        goto out;
    }

    subject_name = X509_get_subject_name(x509_cert);
    rc = addDnToX509Name(subjectDn, subject_name);
    if (!rc) {
        error_msg = "addDnToX509Name(subject)";
    }

    // Add public key for the corresponding certificate to the X509
    // certificate
    if (!X509_set_pubkey(x509_cert, pkey)) {
        error_msg = "X509_set_pubkey";
        goto out;
    }

    // Add serial number to certificate
    if (!setCertificateSerialNumber(x509_cert)) {
        error_msg = "setCertificateSerialNumber";
        goto out;
    }

    // Finalize the certificate
    if (!X509_sign(x509_cert, privateKey_, EVP_sha256())) {
        error_msg = "X509_sign";
        goto out;
    }

    if (!x509ToPemString(cert, x509_cert)) {
        error_msg = "x509ToPemString";
        goto out;
    }

 out:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (x509_cert) {
        X509_free(x509_cert);
    }

    if (error_msg != "") {
        throw CryptoException(error_msg);
    }
}

KeyCertifier::~KeyCertifier() {
    if (privateKey_) {
        EVP_PKEY_free(privateKey_);
    }
}

void certifyKeyAsCA(std::string& cert,
                    const std::string& privateKey,
                    int daysValid) {
    KeyCertifier kc;
    KeyCertifier::fromKeyString(kc, privateKey);

    string publicKey;
    demotePrivateKey(publicKey,
                     privateKey);

    DistinguishedName bogusDn;
    getBogusDistinguishedName(bogusDn);
    kc.generateCertificate(cert,
                           publicKey,
                           bogusDn,
                           bogusDn);
}

int getFirstSubjectCommonName(std::string &out, X509* cert) {
    X509_NAME* name = X509_get_subject_name(cert);
    int idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (idx == -1) {
        return 0;
    }
    int rc = -1;
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
    ASN1_STRING* commonName = X509_NAME_ENTRY_get_data(entry);

    unsigned char* utf8 = nullptr;
    int size = ASN1_STRING_to_UTF8(&utf8, commonName);
    if (size < 0) {
        goto out;
    }

    out.assign((char *)utf8, size);
    rc = 1;

 out:
    if (utf8) {
        OPENSSL_free(utf8);
    }
    return rc;
}

static inline void BN_to_ByteString(const BIGNUM *bn, OpenABEByteString& serial) {
    serial.clear();
    int to_len = BN_num_bytes(bn);
    uint8_t to[to_len];
    BN_bn2bin(bn, to);

    // return the serial number
    serial.appendArray((uint8_t*)to, to_len);
    return;
}

int getSerialNumber(OpenABEByteString& serial, X509* cert) {
    assert(cert != nullptr);
    string error_msg = "";
    int rv = -1;
    BIGNUM *bn_serial = nullptr;

    ASN1_INTEGER *_serial = X509_get_serialNumber(cert);
    if (!_serial) {
        cerr << "get serial number failed" << endl;
        return rv;
    }

    bn_serial = ASN1_INTEGER_to_BN(_serial, NULL);
    if (!bn_serial) {
        cerr << "asn1 to integer failed" << endl;
        return rv;
    }

    BN_to_ByteString(bn_serial, serial);
    rv = 1;

    if (bn_serial)
        BN_free(bn_serial);

    return rv;
}


CertRevList::CertRevList(const string& crl_path) {
    crl_path_ = crl_path;
    crl_ = nullptr;
    crlNumber_ = -1;
    revListSet_ = false;
}

CertRevList::~CertRevList() {
    if (crl_) {
        X509_CRL_free(crl_);
    }
}

void CertRevList::createNewCrl(const std::string& ca_cert, const string& ca_privKey) {
    assert(crl_ == nullptr);
    string error_msg = "";
    EVP_PKEY *pkey = nullptr;
    X509 *cert = nullptr;
//    X509_CRL_INFO *ci = nullptr;
    long version;
    ASN1_TIME *lastUpdate = ASN1_UTCTIME_new();
    ASN1_TIME *nextUpdate = ASN1_UTCTIME_new();

    stringToPkey(&pkey, ca_privKey, true);
    if (!pkey) {
        error_msg = "Could not load CA private key!";
        goto out;
    }

    pemStringToX509(&cert, ca_cert);
    if (!cert) {
        error_msg = "Could not load CA certificate!";
        goto out;
    }

    // X509_check_private_key

    crl_ = X509_CRL_new();
    if(!crl_) {
        error_msg = "Could not allocate X509 CRL structure!";
        goto out;
    }

    if (!X509_CRL_set_issuer_name(crl_, X509_get_subject_name(cert))) {
        error_msg = "Could not set issuer name in CRL.";
        goto out;
    }

    lastUpdate = X509_gmtime_adj(lastUpdate, 0);
    X509_CRL_set_lastUpdate(crl_, lastUpdate);

    nextUpdate = X509_gmtime_adj(nextUpdate, CRL_UPDATE_SCHED);
    X509_CRL_set_nextUpdate(crl_, nextUpdate);

    version = X509_get_version(cert);
    X509_CRL_set_version(crl_, ++version);

//    ci = crl_->crl;
//    ci->issuer = X509_NAME_dup(cert->cert_info->subject);
//    assert(ci->issuer != nullptr);
//
//    X509_gmtime_adj(ci->lastUpdate, 0);
//    if (ci->nextUpdate == nullptr) {
//        ci->nextUpdate = ASN1_UTCTIME_new();
//    }
//    X509_gmtime_adj(ci->nextUpdate, CRL_UPDATE_SCHED);
//    if (!ci->revoked) {
//        ci->revoked = sk_X509_REVOKED_new_null();
//    }
////    if (crlNumber_ >= 0) {
////        if (crl_->crl_number == nullptr)
////            crl_->crl_number = ASN1_INTEGER_new();
////        ASN1_INTEGER_set(crl_->crl_number, crlNumber_);
////    }
//
//    if (ci->version == nullptr) {
//        ci->version = ASN1_INTEGER_new();
//    }
//
//    version = ASN1_INTEGER_get(cert->cert_info->version);
//    ASN1_INTEGER_set(ci->version, ++version);

    if (!X509_CRL_sign(crl_, pkey, EVP_sha256())) {
        error_msg = "Could not sign the CRL list";
        goto out;
    }

    writeCrlFile();
out:
    if (lastUpdate)
        ASN1_UTCTIME_free(lastUpdate);

    if (nextUpdate)
        ASN1_UTCTIME_free(nextUpdate);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (cert)
        X509_free(cert);

    if (error_msg != "") {
        throw CryptoException(error_msg);
    }
}

// load CRL from an existing file
bool CertRevList::loadCrlFile() {
    bool result = true;
    if (crl_ != nullptr) return result; // already loaded

    BIO* io = BIO_new_file((const char *)crl_path_.c_str(), "r");
    assert(io != nullptr);
    crl_ = PEM_read_bio_X509_CRL(io, NULL, NULL, NULL);

    if (crl_ == nullptr) {
        cerr << "Could not load the CRL list" << endl;
        result = false;
    }

    BIO_free(io);
    return result;
}

bool CertRevList::revokeCertificate(const string& client_cert) {
    bool result = false;
    string error_msg = "";
    X509_REVOKED* xr = nullptr;
    X509 *cert = nullptr;
    OpenABEByteString serial;
    //BIGNUM *bn_serial = nullptr;
    ASN1_INTEGER *_serial = nullptr;
    ASN1_TIME *revDate = ASN1_TIME_new();

    if (!crl_) {
        error_msg = "Need to load or create a CRL list";
        goto out;
    }

    pemStringToX509(&cert, client_cert);
    if (!cert) {
        error_msg = "Could not load client certificate!";
        goto out;
    }

    time_t tm;
    time(&tm);

    xr = X509_REVOKED_new();
    assert(xr != nullptr);
    ASN1_TIME_set(revDate, tm);
    X509_REVOKED_set_revocationDate(xr, revDate);

    // for debug purposes!
    getSerialNumber(serial, cert);
    cout << "Serial Number: " << serial.toLowerHex() << endl;
    // get the serial number
    _serial = X509_get_serialNumber(cert);
    if (!_serial) {
        cerr << "get serial number failed" << endl;
        goto out;
    }

    // set the serial number in REVOKED struct
    X509_REVOKED_set_serialNumber(xr, _serial);
    // convert ASN1 to BIGNUM
    //bn_serial = ASN1_INTEGER_to_BN(_serial, NULL);
    // BIGNUM to asn1 integer
    //BN_to_ASN1_INTEGER(bn_serial, xr->serialNumber);
    // now can push revoke
    X509_CRL_add0_revoked(crl_, xr);

    writeCrlFile();

    result = true;
out:
    if (revDate)
        ASN1_TIME_free(revDate);

    //if (bn_serial)
    //    BN_free(bn_serial);

    if (cert)
        X509_free(cert);

    return result;
}

void CertRevList::writeCrlFile() {
    BIO *io = BIO_new_file((const char *)crl_path_.c_str(), "w");
    assert(io != nullptr);
    PEM_write_bio_X509_CRL(io, crl_);
    if (io)
        BIO_free(io);
    return;
}

bool CertRevList::isRevoked(const std::string& client_cert) {
    X509 *cert = nullptr;
    bool result = false;
    string error_msg = "";

    pemStringToX509(&cert, client_cert);
    if (!cert) {
        error_msg = "Could not load client certificate!";
        goto out;
    }

    result = isRevoked(cert);
out:
    if (cert)
        X509_free(cert);

    if (error_msg != "") {
        throw CryptoException(error_msg);
    }

    return result;
}

bool CertRevList::isRevoked(X509 *cert) {
    assert(cert != nullptr);
    string byte_str, error_msg = "";
    bool revoked_status = false;
    STACK_OF(X509_REVOKED) *rev = nullptr;
    X509_REVOKED *r = nullptr;
    ASN1_INTEGER *serial = nullptr;
    OpenABEByteString byte;
    BIGNUM *bn = nullptr;
    //BIO *out = nullptr; 

    if (!crl_) {
        error_msg = "Need to load or create a CRL list";
        goto out;
    }

    serial = X509_get_serialNumber(cert);
    if (revListSet_) {
        // we've optimized CRL loading into memory
        // check whether serial is in the revList_
        bn = ASN1_INTEGER_to_BN(serial, NULL);
        BN_to_ByteString(bn, byte);
        byte_str = byte.toString();
        // loop through each serial number
        for(size_t i = 0; i < revList_.size(); i++) {
            if (revList_[i].compare(byte_str) == 0) {
                revoked_status = true;
                break;
            }
        }
        goto out;
    }

    // otherwise, let's check the loaded CRL
    rev = X509_CRL_get_REVOKED(crl_);

    // out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if(sk_X509_REVOKED_num(rev) == 0) {
        goto out;
    }
    BIO_printf(out, "Revoked Certificates:\n");

    for(int i = 0; i < sk_X509_REVOKED_num(rev); i++) {
        r = sk_X509_REVOKED_value(rev, i);
        const ASN1_INTEGER *serialNumber = X509_REVOKED_get0_serialNumber(r);
        BIO_printf(out,"    Serial Number: ");
        i2a_ASN1_INTEGER(out, serialNumber);
        if (ASN1_INTEGER_cmp(serialNumber, serial) == 0) {
             // BIO_printf(out, "\n        Found the revoked certificate!");
             revoked_status = true;
             break;
        }
    }

out:
    if (bn != nullptr)
        BN_free(bn);

    if (error_msg != "") {
        throw CryptoException(error_msg);
    }

    return revoked_status;
}

bool CertRevList::loadRevokedList() {
    STACK_OF(X509_REVOKED) *rev = nullptr;
    X509_REVOKED *r = nullptr;
    bool status = false;
    OpenABEByteString serial;
    BIGNUM *bn_serial = nullptr;

    if (!crl_) {
        cerr << "Need to load or create a CRL list" << endl;
        goto out;
    }

    rev = X509_CRL_get_REVOKED(crl_);
    if (sk_X509_REVOKED_num(rev) == 0) {
        status = true;
        goto out;
    }

    revList_.clear();
    for(int i = 0; i < sk_X509_REVOKED_num(rev); i++) {
        // get the X509_REVOKED structure
        r = sk_X509_REVOKED_value(rev, i);
        // get serial number from this structure
        const ASN1_INTEGER *serialNumber = X509_REVOKED_get0_serialNumber(r);
        bn_serial = ASN1_INTEGER_to_BN(serialNumber, NULL);
        BN_to_ByteString(bn_serial, serial);
        revList_.push_back(serial.toString());
        BN_free(bn_serial);
    }
    status = true;
out:
    revListSet_ = status;
    return status;
}

}
