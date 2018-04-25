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
/// \file   ZAttributeList.cpp
///
/// \brief  Benchmark utility implementation
///
/// \author J. Ayo Akinyele
///

#include <cstring>
#include <chrono>
#include <openabe/utils/zbenchmark.h>

using namespace std;

int sec_in_microsecond = 1000000;
int ms_in_microsecond = 1000;

void Benchmark::start()
{
  startT = chrono::system_clock::now();
}

void Benchmark::stop()
{
  endT = chrono::system_clock::now();
}

int Benchmark::getTimeInMicroseconds()
{
  if(initBench) {
    return chrono::duration_cast<chrono::microseconds>(endT - startT).count();
  }
  return -1;
}

double Benchmark::computeTimeInMilliseconds()
{
  if (initBench) {
    double microsec_result = (double) this->getTimeInMicroseconds();
    double rawResult = microsec_result / ms_in_microsecond;
    ss << rawResult << ", ";
    sum += rawResult;
    iterationCount++;
    return rawResult;
  }
  return -1.0; // didn't call start
}

string Benchmark::getRawResultString()
{
  return ss.str();
}

double Benchmark::getAverage()
{
  return sum / iterationCount;
}

ListStr::ListStr(void)
{
  // increases as elements are appended
  index = 0;
}

ListStr::~ListStr()
{
  for(int i = 0; i < (int) list.size(); i++)
    list.erase(i);
}

ListStr::ListStr(const ListStr& cList)
{
  //copy constructor
  index = cList.index;
  list = cList.list;
}

void ListStr::append(string & s)
{
  list[index] = s;
  index++;
}

void ListStr::append(string s)
{
  list[index] = s;
  index++;
}

void ListStr::insert(int index, string s)
{
  list[index] = s;
  index++;
}

void ListStr::insert(int index, string & s)
{
  list[index] = s;
  this->index++;
}

int ListStr::searchKey(string index)
{
  for(int i = 0; i < (int) list.size(); i++) {
    if(CheckEqual(index, list[i])) { return i; }
  }
  return -1;
}

string& ListStr::operator[](const int index)
{
  if(index == this->index) { // means we are creating reference.
    this->index++;
    return list[index];
  }
  else if(index < MAX_LIST) {
    return list[index];
  }

  int len = (int) list.size();
  if(index >= 0 && index < len) {
    return list[index];
  }
  else {
    throw new string("Invalid access.\n");
  }
}

ListStr& ListStr::operator=(const ListStr& cList)
{
  if(this == &cList)
    return *this;

  // delete current list contents first
  int i;
  for(i = 0; i < (int) list.size(); i++)
    list.erase(i);
  this->index = 0;

  this->index = cList.index;
  list = cList.list;
  return *this;
}

int ListStr::length()
{
  return (int) list.size();
}

string ListStr::printAtIndex(int index)
{
  stringstream ss;
  int i;

  if(index >= 0 && index < (int) list.size()) {
    i = index;
    ss << list[i];
  }

  string s = ss.str();
  return s;
}

ostream& operator<<(ostream& s, const ListStr& cList)
{
  ListStr cList2 = cList;
  for(int i = 0; i < cList2.length(); i++) {
    if (cList2.printAtIndex(i) != "")
      s << i << ": " << cList2.printAtIndex(i) << endl;
  }

  return s;
}

/* test inequality for two strings */
bool CheckEqual(string value1, string value2)
{
  string s1 = value1;
  string s2 = value2;
  if (std::strcmp(s1.c_str(), s2.c_str()) == 0)
    return true;
  else
    return false;
}
