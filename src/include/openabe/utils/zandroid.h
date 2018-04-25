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
//
/// \file   zandroid.h
///
/// \brief  Header for Android-specific modifications.
///
/// \author Michael Rushanan and J. Ayo Akinyele
///

#ifndef __ZANDROID_H__
#define __ZANDROID_H__

#include <string>
#include <sstream>
#include <cstdlib>

#ifdef ANDROID

namespace std {
// Handling issue with missing std::to_string method in Android.
// https://code.google.com/p/android/issues/detail?id=82791
//
// Solution: well documented on the internet for numerous compilers.
template <typename T>
inline string to_string(T value) {
    ostringstream os_strstream;
    os_strstream << value;
    return os_strstream.str();
}

inline int stoi(string integer) {
    return atoi(integer.c_str());
}

}
#endif

#endif  // __ZANDROID_H__
