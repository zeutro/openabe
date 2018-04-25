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
/// \file   openssl_init.cpp
///
/// \brief  Initialize and cleanup OpenSSL
///
/// \author Alan Dunn
///

#define __OPENSSL_INIT_CPP__

#include <memory>
#include <mutex>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <pthread.h>

#if defined(SSL_LIB_INIT)

#ifndef SSL_library_init
 #define SSL_library_init() OPENSSL_init_ssl(0, NULL)
#endif

#ifndef SSL_load_error_strings
 #define SSL_load_error_strings() \
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS \
                     | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)
#endif

#endif

using namespace std;

struct CRYPTO_dynlock_value {
    mutex the_mutex;
};

static unique_ptr<mutex[]> mutexes;

static void lockingCallback(int mode, int n, const char*, int) {
    if (mode & CRYPTO_LOCK) {
        mutexes[n].lock();
    } else {
        mutexes[n].unlock();
    }
}

static CRYPTO_dynlock_value* dynlockCreate(const char*, int) {
    return new CRYPTO_dynlock_value;
}

static void dynlockLock(int mode,
                        struct CRYPTO_dynlock_value* lock,
                        const char*, int) {
    if (lock != nullptr) {
        if (mode & CRYPTO_LOCK) {
            lock->the_mutex.lock();
        } else {
            lock->the_mutex.unlock();
        }
    }
}

static void dynlockDestroy(struct CRYPTO_dynlock_value* lock,
                           const char*, int) {
    delete lock;
}

void openSslInitialize() {
#if defined(SSL_LIB_INIT)
    SSL_library_init();
    SSL_load_error_strings();
#endif
    // static locking
    mutexes.reset(new mutex[CRYPTO_num_locks()]);
    if (mutexes == nullptr) {
        throw runtime_error("openSslInitialize() failed, "
                            "out of memory while creating mutex array");
    }
    CRYPTO_set_locking_callback(lockingCallback);
    // dynamic locking
    CRYPTO_set_dynlock_create_callback(dynlockCreate);
    CRYPTO_set_dynlock_lock_callback(dynlockLock);
    CRYPTO_set_dynlock_destroy_callback(dynlockDestroy);

    RAND_poll();
}

void openSslCleanup() {
    // dynamic cleanup
    CRYPTO_set_dynlock_create_callback(nullptr);
    CRYPTO_set_dynlock_lock_callback(nullptr);
    CRYPTO_set_dynlock_destroy_callback(nullptr);
    // static cleanup
    CRYPTO_set_locking_callback(nullptr);
    // library cleanup
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    mutexes.reset();
}
