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
/// \file   zattributelist.h
///
///	\brief  Benchmark utility interface
///
/// \author J. Ayo Akinyele
///

#ifndef __ZBENCHMARK_H__
#define __ZBENCHMARK_H__

#include <chrono>
#include <string>
#include <sstream>
#include <map>

#define MAX_LIST	10000000

class Benchmark  {
public:
	Benchmark() { initBench = true; sum = 0.0; iterationCount = 0; };
	~Benchmark() { };
	void start();
	void stop();
	double computeTimeInMilliseconds();
	int getTimeInMicroseconds();
	std::string getRawResultString();
	double getAverage();

private:
	std::chrono::system_clock::time_point startT, endT;
	double sum;
	int iterationCount;
	std::stringstream ss;
	bool initBench;
};

class ListStr  {
public:
  ListStr(void);
  ~ListStr();
  ListStr(const ListStr&);
  void append(std::string&);
  void append(std::string);
  void insert(int, std::string&);
  void insert(int, std::string);
  int length();
  std::string printAtIndex(int index);
  int searchKey(std::string index);
  std::string& operator[](const int index);
  ListStr& operator=(const ListStr&);
  friend std::ostream& operator<<(std::ostream&, const ListStr&);

private:
	int index;
	std::map<int, std::string> list;
};

bool CheckEqual(std::string value1, std::string value2);

#endif
