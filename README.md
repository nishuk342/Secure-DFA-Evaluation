
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
g++ -std=c++20 -maes -msse4 -mavx server.cpp -o server.exe -lcrypto -lws2_32 -Wno-deprecated-declarations
g++ -std=c++20 -maes -msse4 -mavx client.cpp -o client.exe -lcrypto -lws2_32 -Wno-deprecated-declarations
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

