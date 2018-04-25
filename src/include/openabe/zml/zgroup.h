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
/// \file   zgroup.h
///
/// \brief  Base class definition for OpenABE groups (EC/pairings)
///
/// \author J. Ayo Akinyele
///

#ifndef __ZGROUP_H__
#define __ZGROUP_H__

#include <gmpxx.h>

///
/// @class  ZGroup
///
/// @brief  Abstract group for EC/Pairing operations.
///
namespace oabe {

class ZGroup : public ZObject {
public:
  ZGroup(OpenABECurveID id);
  ~ZGroup();
  OpenABECurveID  getCurveID();
  friend std::ostream& operator<<(std::ostream& s, const ZGroup&);

protected:
  OpenABECurveID id;
  std::string group_param;
};

}

#endif /* ifdef __ZGROUP_H__ */
