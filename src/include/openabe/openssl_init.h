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
///	\file   openssl_init.h
///
///	\brief  Initialize and cleanup OpenSSL
///
///	\author Alan Dunn
///

#ifndef __OPENSSL_INIT_H__
#define __OPENSSL_INIT_H__

/*! \brief Initialize OpenSSL
 *
 * This function assumes it has complete responsibility for
 * initializing OpenSSL and may not work correctly if other functions
 * have already done this.
 *
 * Note: This function is not yet Windows compatible.
 *
 * Note: This function is only guaranteed to work with recent versions
 * of OpenSSL (tested on version 1.0.1 or 1.1.0).
 */
void openSslInitialize();

/*! \brief Cleanup OpenSSL
 *
 * @see openSslInitialize
 */
void openSslCleanup();

#endif
