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
/// \file   test_zml.cpp
///
/// \brief  Unit testing utility for Zeutro Math Library
///
/// \author J. Ayo Akinyele
///
///

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <gtest/gtest.h>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include <openabe/utils/zbenchmark.h>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

#define COLOR_STR_GREEN   "\033[32m"
#define COLOR_STR_NORMAL  "\033[0m"
#define COLOR_STR_RED     "\033[31m"

#define EXIT(msg)   cout << msg << endl; goto CLEANUP
#define NUM_PAIRING_TESTS           10
#define ASSERT_RESULT(condition, msg)   if(condition) { \
    cout << "FAIL: " << msg << endl; \
    return false; }

// Global test counters
uint32_t    gNumTests        = 0;
uint32_t    gSuccessfulTests = 0;
#define TEST_DESCRIPTION(desc) RecordProperty("description", desc)
#define TESTSUITE_DESCRIPTION(desc) ::testing::Test::RecordProperty("description", desc)

namespace {

class ZeutroMathLib : public ::testing::Test {
protected:
  virtual void SetUp() {
    string seed;
    pgroup_.reset(new OpenABEPairing(DEFAULT_BP_PARAM));
    rng_.reset(new OpenABERNG());
  }

  // virtual void TearDown() {}
  unique_ptr<OpenABEPairing> pgroup_;
  unique_ptr<OpenABERNG> rng_;
  //  OpenABEByteString entropy_, hashSeed_;
  //  unique_ptr<OpenABECTR_DRBG> rng_;
};

TEST_F(ZeutroMathLib, InitZP) {
  TEST_DESCRIPTION("Testing that init ZP works correctly");
  ZP a;
  pgroup_->initZP(a, 1234567890);
  string b = "499602D2"; // string representation of 1234567890
  string str_a = a.getBytesAsString();
  cout << "ZP: " << str_a << endl;

  ASSERT_EQ(str_a, b);
}

TEST_F(ZeutroMathLib, InitPairingGroup) {
  TEST_DESCRIPTION("Testing that pairing group init works as expected");
  int len = 0;
  char *str = zml_bignum_toHex(pgroup_->order, &len);
  string s0 = string(str, len);
  zml_bignum_safe_free(str);
  cout << "order: " << s0 << endl;
  ASSERT_TRUE(s0 != "");
}

TEST_F(ZeutroMathLib, NegateZP) {
  TEST_DESCRIPTION("Testing that ZP negation works correctly");
  ZP a = pgroup_->randomZP(rng_.get());
  ZP zero;
  pgroup_->initZP(zero, 0);
  cout << "Output: a = " << a << endl;
  cout << "Negation: -a = " << -a << endl;
  ZP b = (a + -a);
  cout << "a + -a = " << b << endl;
  ASSERT_TRUE(a != -a);
  ASSERT_EQ(b, zero);
}

TEST_F(ZeutroMathLib, AddZP) {
  TEST_DESCRIPTION("Testing modulo addition is correct");
  ZP a = pgroup_->randomZP(rng_.get());
  ZP b = pgroup_->randomZP(rng_.get());
  // make sure it is commutative
  ASSERT_EQ(a + b, b + a);
}

TEST_F(ZeutroMathLib, SubtractZP) {
  TEST_DESCRIPTION("Testing modulo subtraction is correct");
  ZP a = pgroup_->randomZP(rng_.get());
  ZP b = pgroup_->randomZP(rng_.get());
  // subtraction is equivalent to negation and addition
  ASSERT_EQ(a - b, a + -b);
}

TEST_F(ZeutroMathLib, RandomZP) {
  TEST_DESCRIPTION("Testing that random ZP works correctly");
  ZP a = pgroup_->randomZP(rng_.get());
  ZP b = pgroup_->randomZP(rng_.get());
  ASSERT_TRUE(a != b);
}

TEST_F(ZeutroMathLib, MultInverseZP) {
  TEST_DESCRIPTION("Testing that multiplicative inverse of a ZP element works correctly");
  ZP a = pgroup_->randomZP(rng_.get());
  ZP c = a;
  c.multInverse();
  ZP one;
  pgroup_->initZP(one, 1);
  cout << "c = inv(a) : " << c << endl;
  cout << "a * c = " << (a * c) << endl;

  ASSERT_EQ(one, a * c);
}

TEST_F(ZeutroMathLib, MultiplyAndDivideZP) {
  TEST_DESCRIPTION("Testing that multiplication and division for ZP elements works correctly");
  ZP x = pgroup_->randomZP(rng_.get());
  ZP y = pgroup_->randomZP(rng_.get());
  ZP z = x * y;
  cout << "z = x * y => " << z << endl;
  ZP t = z / y;
  // cout << "(z / y) == x ? " << ((t == x) ? "true" : "false") << endl;
  ASSERT_EQ(t, x);
  ZP u = z / x;
  // cout << "(z / x) == y ? " << ((u == y) ? "true" : "false") << endl;
  ASSERT_EQ(u, y);
}

TEST_F(ZeutroMathLib, ByteStringsForZP) {
  TEST_DESCRIPTION("Testing that byte string rep is consistent for ZP elements");
  ZP x = pgroup_->randomZP(rng_.get());
  OpenABEByteString z1;
  z1 = x.getByteString();
  string hex_of_raw = z1.toHex();
  cout << "x in raw bin: " << hex_of_raw << endl;
  string s = x.getBytesAsString();
  cout << "x in str hex: " << s << endl;

  ASSERT_EQ(hex_of_raw, s);
}

TEST_F(ZeutroMathLib, SerializeZP) {
  TEST_DESCRIPTION("Testing that ZP serialize/deserialize works correctly");
  OpenABEByteString z1;
  ZP x0 = pgroup_->randomZP(rng_.get());
  x0.serialize(z1);
  cout << "x0 out: " << z1.toLowerHex() << endl;
  ZP x1;
  pgroup_->initZP(x1, 0);
  x1.deserialize(z1);

  ASSERT_EQ(x0, x1);
}

TEST_F(ZeutroMathLib, DivideZPByAConstant) {
  TEST_DESCRIPTION("Testing that ZP can be divided by an integer");
  ZP x = pgroup_->randomZP(rng_.get());

  ZP y1 = x / ZP(2);
  ZP y2 = x / ZP(-2);
  cout << "x / 2 = " <<  y1 << endl;
  cout << "x / -2 = " <<  y2 << endl;

  ASSERT_EQ(x, y1 * ZP(2));
  ASSERT_EQ(x, y2 * ZP(-2));
}

TEST_F(ZeutroMathLib, ExponentiateZP) {
  TEST_DESCRIPTION("Testing that exponentiation with ZP works correctly");
  ZP x = pgroup_->randomZP(rng_.get());
  ZP a;
  pgroup_->initZP(a, 1234567890);

  ZP y = power(x, a);
  cout << "power(x, 1234567890) => " << y << endl;
  // cout << "power(x, a) => " << power(x, a) << endl;
  ASSERT_EQ(y, power(x, 1234567890));
}

TEST_F(ZeutroMathLib, DivisionWithZPConstants) {
  TEST_DESCRIPTION("Testing that division still works for small constants (used in LSSS recovery)");
  ZP zero, one, two;
  pgroup_->initZP(zero, 0);
  pgroup_->initZP(one, 1);
  pgroup_->initZP(two, 2);

  ZP z0 = (zero - one) / (two - one);
  // ZP z0 = ((ZP(0) - ZP(1)) / (ZP(2) - ZP(1)));
  cout << "z0: " << z0 << endl;

  ASSERT_TRUE(z0.ismember());
}

TEST_F(ZeutroMathLib, LeftAndRightShiftZP) {
  TEST_DESCRIPTION("Testing logical shift operation for ZP");

  ZP x = pgroup_->randomZP(rng_.get());

  ASSERT_EQ(x, (x << 128) >> 128);
}

TEST_F(ZeutroMathLib, LogicalOperatorsWithZP) {
  TEST_DESCRIPTION("Testing the logical comparison operators for ZP");
  ZP zero, ten, twenty;
  pgroup_->initZP(zero, 0);
  pgroup_->initZP(ten, 10);
  pgroup_->initZP(twenty, 20);

  ZP x = pgroup_->randomZP(rng_.get());
  ASSERT_TRUE(ten < x);
  ASSERT_TRUE(x > twenty);
  ASSERT_TRUE(ten <= twenty);
  ASSERT_TRUE(x >= zero);
  ASSERT_FALSE(x != x);
}

////// G1 unit tests //////
TEST_F(ZeutroMathLib, RandomG1) {
  TEST_DESCRIPTION("Testing that random G1 works correctly");
  G1 a = pgroup_->randomG1(rng_.get());
  G1 b = pgroup_->randomG1(rng_.get());
#if defined(BP_WITH_OPENSSL)
  ASSERT_TRUE(a == b);
#else
  ASSERT_TRUE(a != b);
#endif
}

TEST_F(ZeutroMathLib, MulG1Tests) {
  TEST_DESCRIPTION("Testing that multiplication with G1 works correctly");
  G1 g = pgroup_->randomG1(rng_.get());
  G1 h = pgroup_->randomG1(rng_.get());
  cout << "(mul) z = (g * h) => " << g * h << endl;
  ASSERT_EQ(g * h, h * g);
}

TEST_F(ZeutroMathLib, DivG1Tests) {
  TEST_DESCRIPTION("Testing that division with G1 works correctly");
  G1 g = pgroup_->randomG1(rng_.get());
  G1 h = pgroup_->randomG1(rng_.get());
  G1 i = g / h;
  cout << "(div) i == (g / h) => " << i << endl;
  ASSERT_EQ(g, i * h);
}

TEST_F(ZeutroMathLib, NegateG1Tests) {
  TEST_DESCRIPTION("Testing that negation with G1 works correctly");
  G1 g = pgroup_->randomG1(rng_.get());
  G1 k = -g;
  cout << "(negation) k = -g: " << k << endl;
  ASSERT_EQ(g, -k);
}

TEST_F(ZeutroMathLib, ExpG1Tests) {
  TEST_DESCRIPTION("Testing that exponentiation with G1 works correctly");
  G1 g = pgroup_->randomG1(rng_.get());
  ZP r = pgroup_->randomZP(rng_.get());
  G1 a = g.exp(r);
  cout << "(exp) a = (g^r) => " << a << endl;
  ZP z = r;
  z.multInverse();
  ASSERT_EQ(a.exp(z), g);
}

TEST_F(ZeutroMathLib, SerializeG1) {
  TEST_DESCRIPTION("Testing that G1 serialize/deserialize works correctly");
  G1 g = pgroup_->randomG1(rng_.get());
  OpenABEByteString tmp;
  g.serialize(tmp);
  cout << "serialized a => " << tmp.toHex() << endl;

  G1 b = pgroup_->initG1();
  b.deserialize(tmp);
  ASSERT_EQ(g, b);
}

TEST_F(ZeutroMathLib, MembershipTestG1) {
  TEST_DESCRIPTION("Testing that G1 membership check is correct");
  G1 g = pgroup_->randomG1(rng_.get());
  ASSERT_TRUE(g.ismember(pgroup_->order));
}

TEST_F(ZeutroMathLib, HashToG1) {
  TEST_DESCRIPTION("Testing hashing to G1 works as expected");
  OpenABEByteString f;
  string message1 = "hello world", message2 = "hello w0rld";

  rng_->getRandomBytes(&f, HASH_LEN);
  G1 F = pgroup_->hashToG1(f, message1);
  cout << "(hash to G1) F => " << F << endl;

  G1 H = pgroup_->hashToG1(f, message2);
  cout << "(hash to G1) H => " << H << endl;

  ASSERT_TRUE(F != H);
}


////// G2 unit tests //////
TEST_F(ZeutroMathLib, RandomG2) {
  TEST_DESCRIPTION("Testing that random G2 works correctly");
  G2 a = pgroup_->randomG2(rng_.get());
  G2 b = pgroup_->randomG2(rng_.get());
#if defined(BP_WITH_OPENSSL)
  ASSERT_TRUE(a == b);
#else
  ASSERT_TRUE(a != b);
#endif
}

TEST_F(ZeutroMathLib, MulG2Tests) {
  TEST_DESCRIPTION("Testing that multiplication with G2 works correctly");
  G2 g = pgroup_->randomG2(rng_.get());
  G2 h = pgroup_->randomG2(rng_.get());
  cout << "(mul) z = (g * h) => " << g * h << endl;
  ASSERT_EQ(g * h, h * g);
}

TEST_F(ZeutroMathLib, DivG2Tests) {
  TEST_DESCRIPTION("Testing that division with G2 works correctly");
  G2 g = pgroup_->randomG2(rng_.get());
  G2 h = pgroup_->randomG2(rng_.get());
  G2 i = g / h;
  cout << "(div) i == (g / h) => " << i << endl;
  ASSERT_EQ(g, i * h);
}

TEST_F(ZeutroMathLib, NegateG2Tests) {
  TEST_DESCRIPTION("Testing that negation with G2 works correctly");
  G2 g = pgroup_->randomG2(rng_.get());
  G2 k = -g;
  cout << "(negation) k = -g: " << k << endl;
  ASSERT_EQ(g, -k);
}

TEST_F(ZeutroMathLib, ExpG2Tests) {
  TEST_DESCRIPTION("Testing that exponentiation with G2 works correctly");
  G2 g = pgroup_->randomG2(rng_.get());
  ZP r = pgroup_->randomZP(rng_.get());
  G2 a = g.exp(r);
  cout << "(exp) a = (g^r) => " << a << endl;
  ZP z = r;
  z.multInverse();
  ASSERT_EQ(a.exp(z), g);
}

TEST_F(ZeutroMathLib, SerializeG2) {
  TEST_DESCRIPTION("Testing that G2 serialize/deserialize works correctly");
  G2 g = pgroup_->randomG2(rng_.get());
  OpenABEByteString tmp;
  g.serialize(tmp);
  cout << "serialized a => " << tmp.toHex() << endl;

  G2 b = pgroup_->initG2();
  b.deserialize(tmp);
  ASSERT_EQ(g, b);
}

TEST_F(ZeutroMathLib, MembershipTestG2) {
  TEST_DESCRIPTION("Testing that G1 membership check is correct");
  G2 g = pgroup_->randomG2(rng_.get());
  ASSERT_TRUE(g.ismember(pgroup_->order));
}

////// GT unit tests //////
TEST_F(ZeutroMathLib, MulGTTests) {
  TEST_DESCRIPTION("Testing that multiplication with GT works correctly");
  G1 g1 = pgroup_->randomG1(rng_.get());
  G2 g2 = pgroup_->randomG2(rng_.get());
  GT gt1 = pgroup_->pairing(g1,g2);

  GT h = gt1 * gt1;
  ASSERT_EQ(gt1, h / gt1);
}

TEST_F(ZeutroMathLib, DivGTTests) {
  TEST_DESCRIPTION("Testing that division with GT works correctly");
  G1 g1 = pgroup_->randomG1(rng_.get());
  G2 g2 = pgroup_->randomG2(rng_.get());
  GT gt1 = pgroup_->pairing(g1,g2);

  GT h = gt1 / gt1;
  ASSERT_EQ(gt1, h * gt1);
}

TEST_F(ZeutroMathLib, NegateGTTests) {
  TEST_DESCRIPTION("Testing that negation with GT works correctly");
  G1 g1 = pgroup_->randomG1(rng_.get());
  G2 g2 = pgroup_->randomG2(rng_.get());
  GT gt = pgroup_->pairing(g1,g2);

  GT k = -gt;
  cout << "(negation) k = -gt: " << k << endl;
  ASSERT_EQ(gt, -k);
}

TEST_F(ZeutroMathLib, ExpGTTests) {
  TEST_DESCRIPTION("Testing that exponentiation with GT works correctly");
  G1 g1 = pgroup_->randomG1(rng_.get());
  G2 g2 = pgroup_->randomG2(rng_.get());
  GT gt = pgroup_->pairing(g1,g2);

  ZP r = pgroup_->randomZP(rng_.get());
  GT a = gt.exp(r);
  cout << "(exp) a = (g^r) => " << a << endl;
  ZP z = r;
  z.multInverse();
  ASSERT_EQ(a.exp(z), gt);
}

TEST_F(ZeutroMathLib, SerializeGT) {
  TEST_DESCRIPTION("Testing that GT serialize/deserialize works correctly");
  G1 g1 = pgroup_->randomG1(rng_.get());
  G2 g2 = pgroup_->randomG2(rng_.get());
  GT gt = pgroup_->pairing(g1,g2);

  OpenABEByteString tmp;
  gt.serialize(tmp);
  cout << "serialized a => " << tmp.toHex() << endl;

  GT b = pgroup_->initGT();
  b.deserialize(tmp);
  ASSERT_EQ(gt, b);
}

TEST_F(ZeutroMathLib, MembershipTestGT) {
  TEST_DESCRIPTION("Testing that GT membership check is correct");
  G1 g1 = pgroup_->randomG1(rng_.get());
  G2 g2 = pgroup_->randomG2(rng_.get());
  GT gt = pgroup_->pairing(g1,g2);
  ASSERT_TRUE(gt.ismember(pgroup_->order));
}

}

int main(int argc, char **argv)
{
  int rc;

  InitializeOpenABE();

  ::testing::InitGoogleTest(&argc, argv);
  rc = RUN_ALL_TESTS();

  ShutdownOpenABE();

  return rc;
}
