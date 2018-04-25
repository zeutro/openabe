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
/// \file   bench_libopenabe.cpp
///
/// \brief  Benchmarking utility for the OpenABE
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <math.h>

#include <openabe/openabe.h>
#include <openabe/utils/zbenchmark.h>
#if defined(USE_BOOST)
#define BOOST_SPIRIT_THREADSAFE
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#endif

using namespace std;
using namespace oabe;

#define	DEFAULT_SECURITY_LEVEL		128
#define FIXED_CMD  "fixed"
#define RANGE_CMD  "range"

#define CPABE	"CP"
#define KPABE	"KP"

#define CPA     "cpa"
#define CCA     "cca"
#define EXIT(msg)	cout << msg << endl; goto CLEANUP

const string mapToJsonString(map<string,string>& data) {
  stringstream ss;
  int data_size = data.size();
  bool has_one = (data_size > 0) ? true : false;
  string data_json = "";

#if defined(USE_BOOST)
  boost::property_tree::ptree pt;

  for(auto& d : data) {
    // keep this simple...
    pt.put(d.first, d.second);
  }
  boost::property_tree::json_parser::write_json(ss, pt);
#else
  int c = 0;
  ss << "{" << endl;
  for (auto& d : data) {
    c++;
    ss << "\t\"" << d.first << "\": \"" << d.second << "\"";
    if (c < data_size) { ss << ","; }
    ss << endl;
  }
  ss << "}" << endl;
#endif
  if (has_one)
    data_json = ss.str();
  return data_json;
}


bool isEqual(string value1, string value2)
{
  string s1 = value1;
  string s2 = value2;
  if (strcmp(s1.c_str(), s2.c_str()) == 0)
    return true;
  else
    return false;
}

string createAttribute(const string& prefix, int i)
{
  stringstream ss;
  if (prefix == "")
    ss << "Attr" << i;
  else
    ss << prefix << ":Attr" << i;
  return ss.str();
}

bool getAttributes(const string& prefix, int max, vector<string> & attrList)
{
  if(max < 0) { return false; }

  for(int i = 0; i < max; i++) {
    attrList.push_back(createAttribute(prefix, i));
  }
  return true;
}

// returns an evenly distributed / balanced policy tree
string getBalancedOpenABETree(const string& prefix, int start, int end) {
  if(start == end) { return createAttribute(prefix, start); }
  int mid = ceil((start + (end - start) / 2.0));
  if(mid == 0) {
    return "(" + createAttribute(prefix, start) + " and " + createAttribute(prefix, end) + ")";
  }
  else {
    return "(" + getBalancedOpenABETree(prefix, start, mid-1) + " and " + getBalancedOpenABETree(prefix, mid, end) + ")";
  }
}

//string getPolicyString(int max)
//{
//    return getBalancedOpenABETree(0, max-1);
//}

string getPolicyString(const string& prefix, int max)
{
  string policystr;
  if(max >= 2) {
    policystr = "(" + createAttribute(prefix, 0) + " and " + createAttribute(prefix, 1) + ")";
  }
  else if(max == 1) {
    policystr = createAttribute(prefix, 0);
  }

	for(int i = 2; i < max; i++)
	{
		policystr = "(" + policystr + " and " + createAttribute(prefix, i) + ")";
	}

	return policystr;
}

string getSchemeString(OpenABE_SCHEME scheme_type)
{
	if(scheme_type == OpenABE_SCHEME_CP_WATERS)
		return "CP-ABE";
	else if(scheme_type == OpenABE_SCHEME_KP_GPSW)
		return "KP-ABE";
	else
		throw runtime_error("Invalid scheme type");
}

///////////////////////////////////////////////////////////////////////////////////
/// Benchmark routines for CP-ABE Waters '11 and KP-ABE GPSW ///
///////////////////////////////////////////////////////////////////////////////////

void benchmarkABE_CPA_KEM(map<string,string>& data, OpenABE_SCHEME scheme_type, ofstream & outfile0,
		                  ofstream & outfile1, ofstream & outfile2, int attributeCount,
		                  int iterationCount, ListStr & encryptResults, ListStr & keygenResults,
		                  ListStr & decryptResults, bool verbose)
{
  data["scheme"] = getSchemeString(scheme_type);
  data["security"] = "CPA_KEM";
  Benchmark benchE, benchD, benchK;
  OpenABE_ERROR res;
  double en_in_ms, de_in_ms, kg_in_ms;
  stringstream s0, s1, s2;
  string mpk, msk, auth1mpk, auth1msk, decKey = "decKey", decKeyBench = "decKeyBench";
  std::unique_ptr<OpenABEFunctionInput> keyFuncInput = nullptr, encFuncInput = nullptr;
  shared_ptr<OpenABESymKey> symkey = nullptr, newkey = nullptr;
  unique_ptr<OpenABECiphertext> ciphertext = nullptr;
  unique_ptr<OpenABEContextABE> context = nullptr;
  unique_ptr<OpenABERNG> rng(new OpenABERNG);
  string prefix = "";

  // get the attribute list
  vector<string> S;
  getAttributes(prefix, attributeCount, S);
  // Initialize a OpenABEContext structure
  context.reset(OpenABE_createContextABE(&rng, scheme_type));
  if (context == nullptr) {
    EXIT("Unable to create a new context");
  }

  if(scheme_type == OpenABE_SCHEME_CP_WATERS || scheme_type == OpenABE_SCHEME_KP_GPSW) {
    mpk = "MPK";
    msk = "MSK";
    // Generate a set of parameters for an ABE authority
    if (context->generateParams(DEFAULT_BP_PARAM, mpk, msk) != OpenABE_NOERROR) {
      EXIT("Unable to generate params");
    }
  } else {
    EXIT("ERROR: not one of the supported scheme types");
  }

  // get attributes from
  if(scheme_type == OpenABE_SCHEME_CP_WATERS) {
    // attributes are embedded in the key
    keyFuncInput.reset(new OpenABEAttributeList(S.size(), S));
    cout << "<== ATTRIBUTES ==>" << keyFuncInput->toString() << "<== ATTRIBUTES ==>\n"; // DEBUG

    // policy is embedded in the ciphertext
    string policy_str =  getPolicyString(prefix, attributeCount);
    encFuncInput = std::unique_ptr<OpenABEFunctionInput>(createPolicyTree(policy_str));
    //cout << "<=== FUNC INPUT ===>\n" << policy_str << "<=== FUNC INPUT ===>\n";
  }
  else if(scheme_type == OpenABE_SCHEME_KP_GPSW) {
    // policy is embedded in the key
    string policy_str =  getPolicyString(prefix, attributeCount);
    keyFuncInput = std::unique_ptr<OpenABEFunctionInput>(createPolicyTree(policy_str));

    // attributes are embedded in the ciphertext
    encFuncInput.reset(new OpenABEAttributeList(S.size(), S));
    cout << "<== ATTRIBUTES ==>" << encFuncInput->toString() << "<== ATTRIBUTES ==>\n"; // DEBUG
  }

  // generate key used for decryption
  res = context->generateDecryptionKey(keyFuncInput.get(), decKey, mpk, msk);

  // benchmarking key generation
  cout << "Testing with " << S.size() << " attributes" << endl;
  for(int i = 0; i < iterationCount; i++) {
    benchK.start();
    res = context->generateDecryptionKey(keyFuncInput.get(), decKeyBench, mpk, msk);
    benchK.stop();
    kg_in_ms = benchK.computeTimeInMilliseconds();
    if(res != OpenABE_NOERROR) { cout << "Fail: " << OpenABE_errorToString(res) << ", time: " << kg_in_ms << " ms" << endl; EXIT("failed to generate key"); }
    context->getKeystore()->deleteKey(decKeyBench);
  }
  cout << "Keygen avg: " << benchK.getAverage() << " ms" << endl;
  data["keygen"] = std::to_string(benchK.getAverage());
  s1 << attributeCount << " " << benchK.getAverage() << endl;
  outfile1 << s1.str();
  keygenResults[attributeCount] = benchK.getRawResultString();

  // benchmarking encryption
  for(int i = 0; i < iterationCount; i++) {
    symkey.reset(new OpenABESymKey);
    ciphertext.reset(new OpenABECiphertext);
    benchE.start();
    res = context->encryptKEM(nullptr, mpk, encFuncInput.get(), DEFAULT_SYM_KEY_BYTES, symkey, ciphertext.get());
    benchE.stop();
    en_in_ms = benchE.computeTimeInMilliseconds();
    if(res != OpenABE_NOERROR) { cout << "Fail: " << OpenABE_errorToString(res) << ", time: " << en_in_ms << " ms" << endl; }
  }
  // get encryption measurements
  cout << "Encrypt avg: " << benchE.getAverage() << " ms" << endl;
  data["encrypt"] = std::to_string(benchE.getAverage());
  s0 << attributeCount << " " << benchE.getAverage() << endl;
  outfile0 << s0.str();
  encryptResults[attributeCount] = benchE.getRawResultString();

  // benchmarking decryption
  for(int i = 0; i < iterationCount; i++) {
    newkey.reset(new OpenABESymKey);
    benchD.start();
    res = context->decryptKEM(mpk, decKey, ciphertext.get(), DEFAULT_SYM_KEY_BYTES, newkey);
    benchD.stop();
    de_in_ms = benchD.computeTimeInMilliseconds();
    if(res != OpenABE_NOERROR) { cout << "Fail: " << OpenABE_errorToString(res) << ", time: " << de_in_ms << " ms" << endl; }
  }
  // get decryption measurements
  cout << "Decrypt avg: " << benchD.getAverage() << " ms" << endl;
  data["decrypt"] = std::to_string(benchD.getAverage());
  s2 << attributeCount << " " << benchD.getAverage() << endl;
  outfile2 << s2.str();
  decryptResults[attributeCount] = benchD.getRawResultString();

  if(CheckEqual(newkey->toString(), symkey->toString())) {
    cout << "Succesful Decryption!\n";
  }
  else {
    cout << "FAILED DECRYPTION!!!\n";
  }
CLEANUP:
  return;
}

void benchmarkABE_CCA_KEM(map<string,string>& data, OpenABE_SCHEME scheme_type, ofstream & outfile0, ofstream & outfile1,
		                  ofstream & outfile2, int attributeCount, int iterationCount, ListStr & encryptResults,
		                  ListStr & keygenResults, ListStr & decryptResults, bool verbose)
{
  data["scheme"] = getSchemeString(scheme_type);
  data["security"] = "CCA_KEM";
  Benchmark benchE, benchD, benchK;
  OpenABE_ERROR res;
  double en_in_ms, de_in_ms, kg_in_ms;
  stringstream s0, s1, s2;
  string mpk, msk, auth1mpk, auth1msk, decKey = "decKey", decKeyBench = "decKeyBench";
  std::unique_ptr<OpenABEFunctionInput> keyFuncInput = nullptr, encFuncInput = nullptr;
  shared_ptr<OpenABESymKey> symkey = nullptr, newkey = nullptr;
  unique_ptr<OpenABECiphertext> ciphertext = nullptr;
  unique_ptr<OpenABEContextCCA> ccaContext = nullptr;
  unique_ptr<OpenABEContextSchemeCPA> schemeContext = nullptr;
  unique_ptr<OpenABERNG> rng(new OpenABERNG), rng2(new OpenABERNG);
  string prefix = "";

  // get the attribute list
  vector<string> S;
  getAttributes(prefix, attributeCount, S);

  // initialize a scheme context with the KEM context
  schemeContext = OpenABE_createContextABESchemeCPA(scheme_type);
  if(!schemeContext) {
    EXIT("Unable to create CPA scheme context");
  }

  // initialize a CCA scheme context
  ccaContext.reset(new OpenABEContextGenericCCA(std::move(schemeContext)));
  if(ccaContext == nullptr) {
    EXIT("Unable to create a new CCA KEM context");
  }

  // generate the parameters for the given scheme_type
  if(scheme_type == OpenABE_SCHEME_CP_WATERS || scheme_type == OpenABE_SCHEME_KP_GPSW) {
    mpk = "MPK";
    msk = "MSK";
    // Generate a set of parameters for an ABE authority
    if (ccaContext->generateParams(DEFAULT_BP_PARAM, mpk, msk) != OpenABE_NOERROR) {
      EXIT("Unable to generate params");
    }
  } else {
    cout << "ERROR: not one of the supported scheme types" << endl;
    return;
  }

  // get attributes from
  if(scheme_type == OpenABE_SCHEME_CP_WATERS) {
    // attributes are embedded in the key
    keyFuncInput.reset(new OpenABEAttributeList(S.size(), S));
    if (verbose) cout << "<== ATTRIBUTES ==>" << keyFuncInput->toString() << "<== ATTRIBUTES ==>\n";

    // policy is embedded in the ciphertext
    string policy_str =  getPolicyString(prefix, attributeCount);
    encFuncInput = std::unique_ptr<OpenABEFunctionInput>(createPolicyTree(policy_str));
  }
  else if(scheme_type == OpenABE_SCHEME_KP_GPSW) {
    // policy is embedded in the key
    string policy_str =  getPolicyString(prefix, attributeCount);
    keyFuncInput = std::unique_ptr<OpenABEFunctionInput>(createPolicyTree(policy_str));

    // attributes are embedded in the ciphertext
    encFuncInput.reset(new OpenABEAttributeList(S.size(), S));
    if (verbose) cout << "<== ATTRIBUTES ==>" << encFuncInput->toString() << "<== ATTRIBUTES ==>\n";
  }

  // generate key used for decryption
  res = ccaContext->generateDecryptionKey(keyFuncInput.get(), decKey, mpk, msk);

  // benchmarking key generation
  if (verbose) cout << "Testing with " << S.size() << " attributes" << endl;
  for(int i = 0; i < iterationCount; i++) {
    benchK.start();
    res = ccaContext->generateDecryptionKey(keyFuncInput.get(), decKeyBench, mpk, msk);
    benchK.stop();
    kg_in_ms = benchK.computeTimeInMilliseconds();
    if(res != OpenABE_NOERROR) { cout << "Fail: " << OpenABE_errorToString(res) << ", time: " << kg_in_ms << " ms" << endl; EXIT("failed to generate dec key"); }
    ccaContext->deleteKey(decKeyBench);
  }
  if (verbose) cout << "Keygen avg: " << benchK.getAverage() << " ms" << endl;
  data["keygen"] = std::to_string(benchK.getAverage());
  s1 << attributeCount << " " << benchK.getAverage() << endl;
  outfile1 << s1.str();
  keygenResults[attributeCount] = benchK.getRawResultString();

  // benchmarking encryption
  for(int i = 0; i < iterationCount; i++) {
    symkey.reset(new OpenABESymKey);
    ciphertext.reset(new OpenABECiphertext);
    benchE.start();
    res = ccaContext->encryptKEM(rng2.get(), mpk, encFuncInput.get(), DEFAULT_SYM_KEY_BYTES, symkey, ciphertext.get());
    benchE.stop();
    en_in_ms = benchE.computeTimeInMilliseconds();
    if(res != OpenABE_NOERROR) { cout << "Fail: " << OpenABE_errorToString(res) << ", time: " << en_in_ms << " ms" << endl; }
  }
  // get encryption measurements
  if (verbose) cout << "Encrypt avg: " << benchE.getAverage() << " ms" << endl;
  data["encrypt"] = std::to_string(benchE.getAverage());
  s0 << attributeCount << " " << benchE.getAverage() << endl;
  outfile0 << s0.str();
  encryptResults[attributeCount] = benchE.getRawResultString();

  // benchmarking decryption
  for(int i = 0; i < iterationCount; i++) {
    newkey.reset(new OpenABESymKey);
    benchD.start();
    res = ccaContext->decryptKEM(mpk, decKey, ciphertext.get(), DEFAULT_SYM_KEY_BYTES, newkey);
    benchD.stop();
    de_in_ms = benchD.computeTimeInMilliseconds();
    if(res != OpenABE_NOERROR) { cout << "Fail: " << OpenABE_errorToString(res) << ", time: " << de_in_ms << " ms" << endl; }
  }
  // get decryption measurements
  if (verbose) cout << "Decrypt avg: " << benchD.getAverage() << " ms" << endl;
  data["decrypt"] = std::to_string(benchD.getAverage());
  s2 << attributeCount << " " << benchD.getAverage() << endl;
  outfile2 << s2.str();
  decryptResults[attributeCount] = benchD.getRawResultString();

  if(CheckEqual(newkey->toString(), symkey->toString())) {
   if (verbose) cout << "Succesful Decryption!\n";
  }
  else {
    cout << "FAILED DECRYPTION!!!\n";
  }

CLEANUP:
  return;
}


int runBenchmark(map<string,string>& data, OpenABE_SCHEME scheme_type, string filename, int iterationCount, int attributeCount, string fixOrRange,
		void (*benchmarkFunc)(map<string,string>& data, OpenABE_SCHEME type, ofstream & outfile0, ofstream & outfile1, ofstream & outfile2,
				int attributeCount, int iterationCount, ListStr & encryptResults, ListStr & keygenResults, ListStr & decryptResults, bool verbose))
{
  stringstream s3, s4, s5;
  ofstream outfile0, outfile1, outfile2, outfile3, outfile4, outfile5;
  string f0 = filename + "_encrypt.dat";
  string f1 = filename + "_keygen.dat";
  string f2 = filename + "_decrypt.dat";
  string f3 = filename + "_keygen_raw.txt";
  string f4 = filename + "_decrypt_raw.txt";
  string f5 = filename + "_encrypt_raw.txt";
  outfile0.open(f0.c_str()); // enc
  outfile1.open(f1.c_str());
  outfile2.open(f2.c_str());
  outfile3.open(f3.c_str());
  outfile4.open(f4.c_str());
  outfile5.open(f5.c_str()); // enc

  ListStr encryptResults, keygenResults, decryptResults;
  cout << "Benchmarking " << getSchemeString(scheme_type) << " scheme" << endl;
  if(fixOrRange.compare(RANGE_CMD) == 0) {
    for(int i = 1; i < attributeCount; i++) {
        cout << "Benchmark with " << i << " attributes." << endl;
        benchmarkFunc(data, scheme_type, outfile0, outfile1, outfile2,
                  i, iterationCount, encryptResults, keygenResults, decryptResults, false);
    }
    cout << "Benchmark with " << attributeCount << " attributes." << endl;
    benchmarkFunc(data, scheme_type, outfile0, outfile1, outfile2,
                  attributeCount, iterationCount, encryptResults,
                  keygenResults, decryptResults, true);
    s3 << keygenResults << endl;
    data["keygen"] = s3.str();
    s4 << decryptResults << endl;
    data["decrypt"] = s4.str();
    s5 << encryptResults << endl;
    data["encrypt"] = s5.str();
  } else if(fixOrRange.compare(FIXED_CMD) == 0) {
    cout << "Benchmark with " << attributeCount << " attributes." << endl;
    benchmarkFunc(data, scheme_type, outfile0, outfile1, outfile2,
        attributeCount, iterationCount, encryptResults, keygenResults, decryptResults, true);
    s3 << attributeCount << " " << keygenResults[attributeCount] << endl;
    s4 << attributeCount << " " << decryptResults[attributeCount] << endl;
    s5 << attributeCount << " " << encryptResults[attributeCount] << endl;
  } else {
    cout << "invalid option." << endl;
    return -1;
  }

  outfile3 << s3.str();
  outfile4 << s4.str();
  outfile5 << s5.str();
  outfile0.close();
  outfile1.close();
  outfile2.close();
  outfile3.close();
  outfile4.close();
  outfile5.close();
  return 0;
}

int main(int argc, const char *argv[])
{
  cout << "Math Library: " << DEFAULT_MATH_LIB << endl;
  cout << "Curve Param ID: " << DEFAULT_BP_PARAM << endl;
  if(argc < 7) {
    cout << "OpenABE benchmark utility, v" << (OpenABE_LIBRARY_VERSION / 100.) << endl;
    cout << "Usage " << argv[0] << ": [ scheme => 'CP', 'KP' or 'MA' ] [ iterations ] [ attributes ] [ 'fixed' or 'range' ] [ 'cpa' or 'cca'] [ filename.json ] [ optional: timestamp in secs ]" << endl;
    cout << "\tscheme: the type of ABE scheme to benchmark" << endl;
    cout << "\titerations: the number of iterations per test" << endl;
    cout << "\tattributes: the number of attributes in the policy/attribute list for encryption" << endl;
    cout << "\tfixed or range: run with a fixed number of attributes or as a range from 1 to num. attributes" << endl;
    cout << "\tcpa or cca: chosen-plaintext secure vs chosen-ciphertext secure versions" << endl;
    cout << "\tfilename.json: output file name for result summary in JSON format" << endl;
    cout << "\ttimestamp: an optional timestamp (generated via 'date +%s' via cmd line) to group results based on scheme/security/attributes" << endl;
    cout << "Benchmark Description: records the time to encrypt/decrypt a 256-bit symmetric key using the CPA-KEM or CCA-KEM constructions." << endl;
    return -1;
  }

  string filename = string(argv[0]);
  string schemeType  = argv[1];
  int iterationCount = atoi( argv[2] );
  int attributeCount = atoi( argv[3] );
  string fixOrRange  = string( argv[4] );
  string secType     = string( argv[5] );
  string output_file = string( argv[6] );
  string timestamp = "";
  if (argc == 8) {
    timestamp = string( argv[7] );
  } else {
    uint64_t tstamp = time(NULL);
    timestamp = std::to_string(tstamp);;
  }

  map<string,string> data;
  data["iterations"] = std::to_string(iterationCount);
  data["attributes"] = std::to_string(attributeCount);
  data["measurement"] = fixOrRange;
  data["time"] = "ms";
  data["timestamp"] = timestamp;
  cout << "iterations: " << iterationCount << endl;
  cout << "attributes: " << attributeCount << endl;
  cout << "msmt type: " << fixOrRange << endl;

  InitializeOpenABE();

  // get the scheme type
  OpenABE_SCHEME scheme_type;
  if(schemeType == CPABE) {
    /* benchmark with CP-ABE func */
    scheme_type = OpenABE_SCHEME_CP_WATERS;
  }
  else if(schemeType == KPABE) {
    /* benchmark with KP-ABE func */
    scheme_type = OpenABE_SCHEME_KP_GPSW;
  }
  else {
    /* other scheme types  */
    cout << "Invalid scheme type!" << endl;
    return -1;
  }


  if(secType == CPA) {
    // run all the CPA tests
    cout << "Running the CPA tests" << endl;
    runBenchmark(data, scheme_type, filename, iterationCount, attributeCount, fixOrRange, benchmarkABE_CPA_KEM);
  }
  else if(secType == CCA) {
    // run all the CCA tests
    cout << "Running the CCA tests" << endl;
    runBenchmark(data, scheme_type, filename, iterationCount, attributeCount, fixOrRange, benchmarkABE_CCA_KEM);
  }
  else {
    cout << "Invalid security type! Expected Argument: '" << CPA << "' or '" << CCA << "'" << endl;
    return -1;
  }

  ShutdownOpenABE();

  string data_json = mapToJsonString(data);
  ofstream outfile0;
  outfile0.open(output_file.c_str());
  outfile0 << data_json;
  outfile0.close();
  cout << "Writing " << data_json.size() << " bytes to " << output_file << "." << endl;

  return 0;
}

