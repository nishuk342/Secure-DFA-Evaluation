# Native-C++ FLORAM-style secure DFA evaluation

This version removes the Obliv-C unmasking process and performs the FLORAM
PRF-unmasking step directly in C++ using a two-party Boolean MPC protocol with
helper-preprocessed Beaver AND triples.

## Online protocol

For each input symbol:

1. Compute the additive-shared lookup index
   `j = |Sigma| * q + x`.
2. Compute and open only `d = j-r`.
3. Rotate the XOR-shared DPF point vector by public `d`, obtaining an XOR share
   of `e_j`.
4. PIR the common blinded database
   `DBbar[i] = DB[i] XOR F(k0,i) XOR F(k1,i)`.
5. Securely compute
   `M = F(k0,j) XOR F(k1,j)` using native C++ Boolean MPC. Neither `j` nor the
   peer's key is revealed.
6. Recover the transition word as the XOR share
   `DBbar[j] XOR M = DB[j]`.
7. Convert that XOR-shared state word to additive shares for the next DFA step.

The actual index `j` is never reconstructed. Only `d` is opened, matching the
current thesis design.

## Native C++ unmasking

The secure unmasker is a specialized GMW/Beaver Boolean MPC circuit:

- 64 secure AND gates convert the two additive input shares into XOR-shared
  bits of `j` (two ANDs per bit, so 128 triples).
- AES-128 is evaluated twice: once for `k0` and once for `k1`.
- Each AES uses the NIST AES S-box circuit with 32 AND gates per S-box.
- There are 16 S-boxes per AES round and 10 rounds, so each AES consumes
  `10 * 16 * 32 = 5120` Boolean AND triples.
- Total per input symbol: `128 + 2*5120 = 10368` Boolean triples.

The helper generates and sends these triples but never receives `j`, either
key, the input string, or the transition database.

## PRF convention

The client and native C++ MPC use the same FLORAM-compatible one-word PRF:

`IV = 00 00 00 00 00 00 00 00 || BE64(index)`

`F(k,index) = first 8 bytes of AES-128_k(IV)`

The first eight AES bytes are interpreted as a little-endian `uint64_t`, which
matches the existing client/database representation.

## Files

- `server.cpp` - H/S1/S2 protocol, DPF, rotation, PIR and native secure unmask.
- `client.cpp` - creates the blinded transition database and additive input
  shares; S1 gets only `k0`, S2 gets only `k1`.
- `mpc_dpf.hpp` - existing DPF and arithmetic-share conversion code.
- `floram_mpc_aes.hpp` - native Boolean MPC, AES circuit, and secure PRF
  unmasking.
- `aes_sbox_table.inc` - AES S-box used only for local key expansion; it is
  never applied to the secret key inside the MPC circuit.
- `common.hpp` / `network.hpp` - existing utility/network code.

## Build (MSYS2 UCRT64 / MinGW)

```bash
g++ -std=c++20 -maes -msse4.1 -mavx server.cpp -o server.exe -lcrypto -lws2_32 -Wno-deprecated-declarations
g++ -std=c++20 -maes -msse4.1 -mavx client.cpp -o client.exe -lcrypto -lws2_32 -Wno-deprecated-declarations
```

## Run example

For a 16-entry transition table (`N=16`), depth 4, alphabet size 2 and input
length 5:

Terminal 1:

```bash
./server.exe H 6000 4 5
```

Terminal 2:

```bash
./server.exe S1 5001 6000 7001 4 16 2
```

Terminal 3:

```bash
./server.exe S2 127.0.0.1 5001 127.0.0.1 6000 7002 4 16 2
```

Terminal 4:

```bash
./client.exe 127.0.0.1 7001 127.0.0.1 7002 transition.txt 10110 2
```

There is no separate unmask port and no Obliv-C process.

## Security model

The implementation is intended for the same semi-honest, non-colluding
S1/S2/helper setting used by the current prototype. The helper sees only
preprocessed correlated randomness. The two computation servers exchange only
MPC openings required by the Beaver protocol. The peer never receives the
other server's AES key or additive `j` share.

This is a native-C++ implementation of the missing FLORAM unmasking function,
not a verbatim port of the original FLORAM Obliv-C/garbled-circuit source.
The FLORAM database masking convention is retained, while the secure PRF
computation is implemented with the existing helper-assisted Boolean MPC
architecture.
