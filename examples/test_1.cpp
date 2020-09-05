#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

int main(int argc, char **argv) {
    InitializeOpenABE();
    cout << "Testing CP-ABE context" << endl;

    OpenABECryptoContext cpabe("CP-ABE");
    int pid1TEMP=40 ;
 //   double pid2TEMP=30 ;
    int pid1GLUCUSE=100;
  //  double paid2GLUCUSE=300;
    int pid1HR=77;
  //  double pid2HR=66;
    string ct, pt1 = std::to_string(pid1TEMP &  pid1GLUCUSE & pid1HR);
    string pt2;

    cpabe.generateParams();

    cpabe.keygen("|doctor|family", "key0");

    cpabe.encrypt("doctor and family", pt1, ct);

    bool result = cpabe.decrypt("key0", ct, pt2);

    assert(result && pt1 == pt2);

    cout << "Recovered message: " << pt2 << endl;

    ShutdownOpenABE();
    if(pid1TEMP  >37.5){
        cout << "patined with id1 has a high temrature"<< endl;
    }
    if(pid1GLUCUSE  >200){
        cout << "patined with id1 has a high galcuse level"<< endl;
    }
    if(pid1HR  >100 or pid1HR <60){
        cout << "patined with id1 has a dangerus heart rate"<< endl;
    }

    return 0;
}
