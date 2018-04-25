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
/// \file   zgroup.cpp
///
/// \brief  Base class definition for OpenABE groups (EC/pairings)
///
/// \author J. Ayo Akinyele
///

#define __ZGROUP_CPP__

#include <openabe/openabe.h>

/********************************************************************************
 * Implementation of the ZGroup class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the ZGroup class.
 *
 */

ZGroup::ZGroup(OpenABECurveID id) {
  this->id = id;
  this->group_param = "";
}

/*!
 * Destructor for the ZGroup class.
 *
 */

ZGroup::~ZGroup() {}

OpenABECurveID ZGroup::getCurveID() { return id; }

std::ostream &operator<<(std::ostream &os, const ZGroup &z) {
  os << z.group_param << " : " << z.id;
  return os;
}
}

