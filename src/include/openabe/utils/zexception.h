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
///	\file   zexception.h
///
///	\brief  Convenience exception functionality
///
///	\author Alan Dunn and J. Ayo Akinyele
///

#ifndef __ZEXCEPTION_H__
#define __ZEXCEPTION_H__

#include <exception>
#include <string>

namespace oabe {

/*! \brief Exception that improves ease of creating new exceptions
 *
 * New exceptions that want to have a message need only inherit from
 * MessageException and call its constructor.  See
 * zeutro::crypto::CryptoException for example use.
 */
class MessageException : public std::exception {
public:
  MessageException(const std::string& msg) : msg_(msg) {}
  ~MessageException() throw () {}

  const char* what() const throw() {
    return msg_.c_str();
  }

protected:
  std::string msg_;
};

class CryptoException : public MessageException {
public:
  CryptoException(const std::string& msg) :
      MessageException(msg) {}
};

/*!
 * \brief Exception for the ZCryptoBox interface
 */
class ZCryptoBoxException : public MessageException {
public:
  ZCryptoBoxException(const std::string& msg) :
      MessageException(msg) {}
};


}

#endif
