# Benchmarking

OpenABE is built on top of the abstract Zeutro Math library which supplies all of our elliptic-curve operations. We instantiate our schemes using the state-of-the-art Barreto-Naehrig (BN) curves with the embedding degree `k = 12` (commonly referred to as `BN-254`). This particular asymmetric curve is known to yield a very efficient pairing implementation and a security level equivalent to `AES-128`. As a result, this boosts the overall performance of ABE scheme implementations over prior efforts. Other benefits of BN curves include the ability to compress the representation of group elements. This directly translates to making ABE ciphertexts more compact which considerably reduces transmission costs.

## The benchmark utility

OpenABE includes a benchmark utility for all the ABE schemes it provides:

```text
Math Library: RELIC
OpenABE benchmark utility, v1.0
Usage bench_libopenabe: [ scheme => 'CP' or 'KP' ] [ iterations ] \
               [ attributes ] [ 'fixed' or 'range' ] [ 'cpa' or 'cca']
-scheme: the type of ABE scheme to benchmark
-iterations: the number of iterations per test
-attributes: the number of attributes in the policy or \
             attribute list for encryption
-'fixed' or 'range': run with a fixed number of attributes \
                     or as a range from 1 to num. attributes
-'cpa' or 'cca': chosen-plaintext secure vs chosen-ciphertext \
                 secure versions
```

## Example

The command below benchmarks the CCA-secure KP-ABE implementation with 100 attributes for encryption (averaged over 10 iterations). The generated decryption key policy will have 100 attributes and each attribute will be involved in the decryption.

```bash
cd src
./bench_libopenabe KP 10 100 fixed cca
```

See also the [OpenABE CLI Util Document](libopenabe-v1.0.0-cli-doc.pdf) for more details on the command-line tools.
