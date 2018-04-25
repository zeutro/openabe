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
/// \file   common.cpp
///
/// \brief  Common routines and shared functionality
///
/// \author J. Ayo Akinyele
///

#include "common.h"

using namespace std;
using namespace oabe;

void getFile(std::string &result, const std::string &filename) {
  result.clear();

  fstream fs(filename, fstream::in);
  if (fs.fail()) {
    string msg = "Could not open file ";
    msg += filename;
    throw ios_base::failure(msg);
  }

  fs.exceptions(fstream::badbit);
  while (!fs.eof()) {
    char buf[512];
    fs.read(buf, sizeof(buf));
    result.append(buf, fs.gcount());
  }

  fs.close();
}


OpenABE_SCHEME checkForScheme(string type, string &suffix)
{
    suffix.clear();
    if(type == CP_ABE) {
    	suffix = ".cpabe";
    	return OpenABE_SCHEME_CP_WATERS;
    } else if(type == KP_ABE) {
    	suffix = ".kpabe";
    	return OpenABE_SCHEME_KP_GPSW;
    } else if(type == PK_ENC) {
        suffix = ".pkenc";
        return OpenABE_SCHEME_PK_OPDH;
    } else {
    	return OpenABE_SCHEME_NONE;
    }
}

void addNameSeparator(string &prefix)
{
    // check if last character of prefix is a name separator (if not, add it)
    if(prefix.size() > 0 && prefix[prefix.size()-1] != NAME_SEP) {
    	prefix += NAME_SEP;
    }
    return;
}

// adds an extension if not present
void addFileExtension(string &filename, string ext)
{
    if(filename.find(ext) == string::npos) {
    	filename += ext;
    }
    return;
}

void WriteToFile(const char* filename, string outputStr)
{
    ofstream file;
    file.open(filename);
    file << outputStr;
    file.close();
}

string ReadFile(const char* filename)
{
    ifstream input(filename);
    string line = "";
    // read everthing between the headers
    if (input.is_open()) {
    	while(getline(input, line)) {
    		/* finish this
    		if(line.compare(begin_header) == 0)
    		   continue;
    		*/
    		if(line.find(BLOCK) == std::string::npos) {
    			break;
    		}
    	}
    	input.close();
    }

    return Base64Decode(line);
}

string ReadBlockFromFile(const char* begin_header, const char* end_header, const char* filename)
{
    ifstream input(filename);
    string block = "", line;
    bool found_header = false;
    // read everthing between the headers
    if(input.is_open()) {
    	while(getline(input, line)) {
    		if(line.compare(begin_header) == 0) {
    		   found_header = true;
    			continue;
    		}
    		else if(line.compare(end_header) == 0) {
    			break;
    		}
    		if(found_header) block = line;
    	}
    	input.close();
    }

    return Base64Decode(block);
}

void WriteBinaryFile(const char* filename, string& outputStr)
{
    ofstream file;
    file.open(filename, ios::out | ios::binary);
    file << outputStr;
    file.close();
}

void WriteBinaryFile(const char* filename, uint8_t *buf, uint32_t len)
{
    ofstream file;
    file.open(filename, ios::out | ios::binary);
    // file << outputStr;
    file.write((const char *) buf, (int) len);
    file.close();
}

string ReadBinaryFile(const char* filename)
{
    ifstream input(filename, ios::binary);
    string inputBlob = "", line;
    // read everthing between the headers
    if(input.is_open()) {
    	while(getline(input, line)) {
    		inputBlob += line + "\n";
    	}
    	input.close();
    }

    return inputBlob;
}
