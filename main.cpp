#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <fstream>
#include <string>

#include <libOTe/Tools/LDPC/Mtx.h>
#include <libOTe/Tools/LDPC/Util.h>
#include <libOTe_Tests/Common.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Timer.h>
#include "Paxos.h"
#include "PaxosImpl.h"
#include "SimpleIndex.h"
#include <libdivide.h>
#include "Encryption.h"
#include "SocketComm.h"

using namespace oc;
using namespace volePSI;
using namespace osuCrypto;
using namespace std;

// --- helper: generate values derived from keys using PRNG ---
bool generateAndSaveValues(const vector<block>& keys, const string& valPath)
{
    cout << "Generating values from keys using PRNG..." << endl;
    
    ofstream valFile(valPath);
    if (!valFile.is_open()) {
        cerr << "Failed to open " << valPath << " for writing" << endl;
        return false;
    }
    
    try {
        for (size_t i = 0; i < keys.size(); ++i) {
            // Use PRNG seeded with key to generate derived value
            PRNG prng(keys[i]);
            uint64_t val = prng.get<uint64_t>();
            valFile << val << "\n";
        }
        valFile.close();
        cout << "Generated and saved " << keys.size() << " values to " << valPath << endl;
        return true;
    } catch (const std::exception& e) {
        cerr << "Error generating values: " << e.what() << endl;
        return false;
    }
}

// --- helper: load keys from file and generate values ---
bool loadKeysAndGenerateValues(vector<block>& keys, oc::Matrix<block>& vals,
                               const string& keyPath, const string& valPath)
{
    // Load keys
    ifstream keyFile(keyPath);
    if (!keyFile.is_open()) {
        cerr << "Failed to open " << keyPath << endl;
        return false;
    }

    vector<uint64_t> keyInts;
    uint64_t k;
    while (keyFile >> k) {
        keyInts.push_back(k);
    }
    keyFile.close();

    if (keyInts.empty()) {
        cerr << "No keys found in " << keyPath << endl;
        return false;
    }

    size_t n = keyInts.size();
    keys.resize(n);

    // Convert keys to blocks
    for (size_t i = 0; i < n; ++i) {
        keys[i] = toBlock(keyInts[i]);
    }

    cout << "Successfully loaded " << n << " keys." << endl;

    // Generate and save values from keys
    if (!generateAndSaveValues(keys, valPath)) {
        cerr << "Failed to generate values" << endl;
        return false;
    }

    // Load generated values
    ifstream valFile(valPath);
    if (!valFile.is_open()) {
        cerr << "Failed to open generated " << valPath << endl;
        return false;
    }

    vector<uint64_t> valInts;
    uint64_t v;
    while (valFile >> v) {
        valInts.push_back(v);
    }
    valFile.close();

    vals.resize(n, 1);
    for (size_t i = 0; i < n; ++i) {
        vals(i, 0) = toBlock(valInts[i]);
    }

    cout << "Successfully loaded " << n << " generated values." << endl;
    return true;
}

// --- helper: load keys/values file (unchanged) ---
bool loadKeyValueFromFile(vector<block>& keys, oc::Matrix<block>& vals,
                          const string& keyPath, const string& valPath)
{
    ifstream keyFile(keyPath);
    ifstream valFile(valPath);

    if (!keyFile.is_open() || !valFile.is_open()) {
        cerr << "Failed to open " << keyPath << " or " << valPath << endl;
        return false;
    }

    vector<uint64_t> keyInts, valInts;
    uint64_t k, v;
    while (keyFile >> k && valFile >> v) {
        keyInts.push_back(k);
        valInts.push_back(v);
    }

    if (keyInts.size() != valInts.size()) {
        cerr << "Warning: key and value counts do not match ("
             << keyInts.size() << " vs " << valInts.size()
             << "). Using the smaller count." << endl;
    }

    size_t n = min(keyInts.size(), valInts.size());
    keys.resize(n);
    vals.resize(n, 1);

    for (size_t i = 0; i < n; ++i) {
        keys[i] = toBlock(keyInts[i]);
        vals(i, 0) = toBlock(valInts[i]);
    }

    cout << "Successfully loaded " << n << " key/value pairs." << endl;
    return true;
}

// --- helper: save/load oc::Matrix<block> to/from binary file ---
// Format: uint64_t rows | uint64_t cols | raw blocks (rows*cols * sizeof(block))
bool saveMatrixToFile(const oc::Matrix<block>& M, const string& path)
{
    ofstream out(path, ios::binary);
    if (!out.is_open()) return false;
    uint64_t rows = M.rows();
    uint64_t cols = M.cols();
    uint64_t rn = htobe64(rows);
    uint64_t cn = htobe64(cols);
    out.write(reinterpret_cast<const char*>(&rn), sizeof(rn));
    out.write(reinterpret_cast<const char*>(&cn), sizeof(cn));
    if (rows * cols) {
        out.write(reinterpret_cast<const char*>(M.data()), rows * cols * sizeof(block));
    }
    out.close();
    return true;
}

bool loadMatrixFromFile(oc::Matrix<block>& M, const string& path)
{
    ifstream in(path, ios::binary);
    if (!in.is_open()) return false;
    uint64_t rn = 0, cn = 0;
    in.read(reinterpret_cast<char*>(&rn), sizeof(rn));
    in.read(reinterpret_cast<char*>(&cn), sizeof(cn));
    uint64_t rows = be64toh(rn);
    uint64_t cols = be64toh(cn);
    M.resize(rows, cols);
    if (rows * cols) {
        in.read(reinterpret_cast<char*>(M.data()), rows * cols * sizeof(block));
    }
    in.close();
    return true;
}

// --- Template helpers for encode/decode (mirror of perfPaxosImpl style) ---

template<typename T>
bool encodeOKVS_impl(const vector<block>& keys,
                     const oc::Matrix<block>& vals,
                     oc::Matrix<block>& okvs_out,
                     PaxosParam& pp,
                     u64 seed = 0)
{
    try {
        Paxos<T> paxos;
        paxos.init(keys.size(), pp, block(seed, seed));
        paxos.setInput(keys);

        // okvs_out must be sized rows = pp.size(), cols = vals.cols()
        size_t rows = pp.size();
        size_t cols = vals.cols();
        okvs_out.resize(rows, cols);

        // Use timer around encode
        auto t0 = chrono::high_resolution_clock::now();
        paxos.template encode<block>(vals, okvs_out);
        auto t1 = chrono::high_resolution_clock::now();

        double ms = chrono::duration_cast<chrono::microseconds>(t1 - t0).count() / 1000.0;
        cout << "[encodeOKVS_impl] encode time: " << ms << " ms" << endl;
        return true;
    } catch (exception& e) {
        cerr << "encodeKOvs_impl exception: " << e.what() << endl;
        return false;
    }
}

template<typename T>
bool decodeOKVS_impl(const vector<block>& keys,
                     const oc::Matrix<block>& okvs_in,
                     oc::Matrix<block>& vals_out,
                     PaxosParam& pp,
                     u64 seed = 0)
{
    try {
        Paxos<T> paxos;
        paxos.init(keys.size(), pp, block(seed, seed));

        size_t rows = keys.size();
        size_t cols = okvs_in.cols();
        vals_out.resize(rows, cols);

        auto t0 = chrono::high_resolution_clock::now();
        paxos.template decode<block>(keys, vals_out, okvs_in);
        auto t1 = chrono::high_resolution_clock::now();

        double ms = chrono::duration_cast<chrono::microseconds>(t1 - t0).count() / 1000.0;
        cout << "[decodeOKVS_impl] decode time: " << ms << " ms" << endl;
        return true;
    } catch (exception& e) {
        cerr << "decodeOKVS_impl exception: " << e.what() << endl;
        return false;
    }
}

// dispatch based on bit-size parameter b (8/16/32/64)
bool encodeOKVS_dispatch(int bits,
                         const vector<block>& keys,
                         const oc::Matrix<block>& vals,
                         oc::Matrix<block>& okvs_out,
                         PaxosParam& pp,
                         u64 seed = 0)
{
    switch (bits) {
    case 8:  return encodeOKVS_impl<u8>(keys, vals, okvs_out, pp, seed);
    case 16: return encodeOKVS_impl<u16>(keys, vals, okvs_out, pp, seed);
    case 32: return encodeOKVS_impl<u32>(keys, vals, okvs_out, pp, seed);
    case 64: return encodeOKVS_impl<u64>(keys, vals, okvs_out, pp, seed);
    default:
        cerr << "Unsupported bit size: " << bits << endl;
        return false;
    }
}

bool decodeOKVS_dispatch(int bits,
                         const vector<block>& keys,
                         const oc::Matrix<block>& okvs_in,
                         oc::Matrix<block>& vals_out,
                         PaxosParam& pp,
                         u64 seed = 0)
{
    switch (bits) {
    case 8:  return decodeOKVS_impl<u8>(keys, okvs_in, vals_out, pp, seed);
    case 16: return decodeOKVS_impl<u16>(keys, okvs_in, vals_out, pp, seed);
    case 32: return decodeOKVS_impl<u32>(keys, okvs_in, vals_out, pp, seed);
    case 64: return decodeOKVS_impl<u64>(keys, okvs_in, vals_out, pp, seed);
    default:
        cerr << "Unsupported bit size: " << bits << endl;
        return false;
    }
}


// ---------------- existing perfPaxosImpl / perfPaxos (only lightly modified to keep original behavior) ----------------

template<typename T>
void perfPaxosImpl(oc::CLP& cmd)
{
    auto t = cmd.getOr("t", 1ull);
    auto v = cmd.getOr("v", cmd.isSet("v") ? 1 : 0);
    auto w = cmd.getOr("w", 3);
    auto ssp = cmd.getOr("ssp", 40);
    auto dt = cmd.isSet("binary") ? PaxosParam::Binary : PaxosParam::GF128;
    auto cols = cmd.getOr("cols", 0);

    string keyPath = "../keys.txt";
    string valPath = "../values.txt";

    vector<block> key;
    oc::Matrix<block> val;
    // Load keys and generate values from them
    if (!loadKeysAndGenerateValues(key, val, keyPath, valPath)) {
        return;
    }

    size_t n = key.size();
    auto m = cols ? cols : 1;

    PaxosParam pp(n, w, ssp, dt);
    oc::Matrix<block> pax(pp.size(), m);

    Timer timer;
    auto start = timer.setTimePoint("start");
    auto end = start;

    for (u64 i = 0; i < t; ++i) {
        Paxos<T> paxos;
        paxos.init(n, pp, block(i, i));
        if (v > 1)
            paxos.setTimer(timer);

        if (cols) {
            paxos.setInput(key);
            paxos.template encode<block>(val, pax);
            timer.setTimePoint("s" + std::to_string(i));
            paxos.template decode<block>(key, val, pax);
        } else {
            paxos.template solve<block>(key, oc::span<block>(val), oc::span<block>(pax));
            timer.setTimePoint("s" + std::to_string(i));
            paxos.template decode<block>(key, oc::span<block>(val), oc::span<block>(pax));
        }

        end = timer.setTimePoint("end" + to_string(i));
    }

    if (v) std::cout << timer << std::endl;

    double total_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    cout << "total: " << total_ms << " ms" << endl;
    double D_size_MB = (pp.size() * m * sizeof(block)) / (1024.0 * 1024.0);
    cout << "D vector size: " << D_size_MB << " MB" << endl;
}


void perfPaxos(oc::CLP& cmd)
{
    auto bits = cmd.getOr("b", 16);
    switch (bits) {
    case 8:  perfPaxosImpl<u8>(cmd);  break;
    case 16: perfPaxosImpl<u16>(cmd); break;
    case 32: perfPaxosImpl<u32>(cmd); break;
    case 64: perfPaxosImpl<u64>(cmd); break;
    default:
        cout << "b must be 8,16,32 or 64. " LOCATION << endl;
        throw RTE_LOC;
    }
}

// --- helper: serialize matrix to bytes ---
std::vector<unsigned char> serializeMatrix(const oc::Matrix<block>& M)
{
    uint64_t rows = M.rows();
    uint64_t cols = M.cols();
    uint64_t size = 16 + (rows * cols * sizeof(block)); // 8+8 for rows/cols + data
    
    std::vector<unsigned char> buffer(size);
    uint64_t rn = htobe64(rows);
    uint64_t cn = htobe64(cols);
    
    std::memcpy(buffer.data(), &rn, 8);
    std::memcpy(buffer.data() + 8, &cn, 8);
    
    if (rows * cols > 0) {
        std::memcpy(buffer.data() + 16, M.data(), rows * cols * sizeof(block));
    }
    
    return buffer;
}

// --- helper: deserialize matrix from bytes ---
oc::Matrix<block> deserializeMatrix(const std::vector<unsigned char>& buffer)
{
    if (buffer.size() < 16) {
        cerr << "Buffer too small to deserialize matrix" << endl;
        return {};
    }
    
    uint64_t rn = 0, cn = 0;
    std::memcpy(&rn, buffer.data(), 8);
    std::memcpy(&cn, buffer.data() + 8, 8);
    
    uint64_t rows = be64toh(rn);
    uint64_t cols = be64toh(cn);
    
    oc::Matrix<block> M(rows, cols);
    if (rows * cols > 0) {
        std::memcpy(M.data(), buffer.data() + 16, rows * cols * sizeof(block));
    }
    
    return M;
}

// --- helper: distribute encrypted key and OKVS matrix to servers ---
bool distributeToServers(
    const std::vector<unsigned char>& encryptionKey,
    const oc::Matrix<block>& okvs,
    const std::string& server1, uint16_t port1,
    const std::string& server2, uint16_t port2)
{
    cout << "\n=== Distributing encrypted data to servers ===" << endl;
    
    // Serialize OKVS matrix
    auto okvsData = serializeMatrix(okvs);
    cout << "OKVS matrix serialized: " << okvsData.size() << " bytes" << endl;
    
    try {
        // Connect to server 1 and send encryption key
        cout << "\nConnecting to server 1: " << server1 << ":" << port1 << endl;
        SocketClient client1(server1, port1);
        if (!client1.connect()) {
            cerr << "Failed to connect to server 1" << endl;
            return false;
        }
        
        cout << "Sending encryption key to server 1..." << endl;
        if (!client1.sendWithLength(encryptionKey)) {
            cerr << "Failed to send encryption key to server 1" << endl;
            client1.disconnect();
            return false;
        }
        cout << "Encryption key sent to server 1: " << encryptionKey.size() << " bytes" << endl;
        client1.disconnect();
        
        // Connect to server 2 and send OKVS matrix
        cout << "\nConnecting to server 2: " << server2 << ":" << port2 << endl;
        SocketClient client2(server2, port2);
        if (!client2.connect()) {
            cerr << "Failed to connect to server 2" << endl;
            return false;
        }
        
        cout << "Sending OKVS matrix to server 2..." << endl;
        if (!client2.sendWithLength(okvsData)) {
            cerr << "Failed to send OKVS matrix to server 2" << endl;
            client2.disconnect();
            return false;
        }
        cout << "OKVS matrix sent to server 2: " << okvsData.size() << " bytes" << endl;
        client2.disconnect();
        
        cout << "\n=== Distribution completed successfully ===" << endl;
        return true;
        
    } catch (const std::exception& e) {
        cerr << "Distribution error: " << e.what() << endl;
        return false;
    }
}

// --- helper: encrypt values with the generated key ---
oc::Matrix<block> encryptValues(
    const vector<block>& keys,
    const oc::Matrix<block>& vals,
    const std::vector<unsigned char>& encryptionKey)
{
    cout << "\n=== Encrypting values ===" << endl;
    
    if (encryptionKey.size() != 32) {
        cerr << "Invalid encryption key size" << endl;
        return {};
    }
    
    size_t n = vals.rows();
    size_t cols = vals.cols();
    
    // Store encrypted values with key - each value will be encrypted with derived key
    // Result: encrypted blocks serialized as bytes
    oc::Matrix<block> encryptedVals(n, cols);
    
    try {
        for (size_t i = 0; i < n; ++i) {
            for (size_t j = 0; j < cols; ++j) {
                auto encrypted = Encryption::encryptBlock(vals(i, j), encryptionKey, keys[i]);
                // Store first 16 bytes as block (rest is truncated)
                if (encrypted.size() >= 16) {
                    std::memcpy(encryptedVals(i, j).data(), encrypted.data(), 16);
                }
            }
        }
        cout << "Values encrypted: " << n << " keys x " << cols << " columns" << endl;
        return encryptedVals;
    } catch (const std::exception& e) {
        cerr << "Encryption error: " << e.what() << endl;
        return {};
    }
}

// --- helper: decode OKVS and return encrypted matrix ---
bool encodeWithDistribution(
    int bits,
    const vector<block>& keys,
    const oc::Matrix<block>& vals,
    oc::Matrix<block>& okvs,
    PaxosParam& pp,
    const std::vector<unsigned char>& encryptionKey,
    const string& server1, uint16_t port1,
    const string& server2, uint16_t port2)
{
    cout << "\n=== Starting encoding with distribution ===" << endl;
    
    // Step 1: Encrypt values
    auto encryptedVals = encryptValues(keys, vals, encryptionKey);
    if (encryptedVals.rows() == 0) {
        cerr << "Failed to encrypt values" << endl;
        return false;
    }
    
    // Step 2: Encode encrypted values using OKVS
    cout << "\nEncoding encrypted values into OKVS matrix..." << endl;
    auto t0 = chrono::high_resolution_clock::now();
    bool ok = encodeOKVS_dispatch(bits, keys, encryptedVals, okvs, pp, 0);
    auto t1 = chrono::high_resolution_clock::now();
    double ms = chrono::duration_cast<chrono::microseconds>(t1 - t0).count() / 1000.0;
    
    if (!ok) {
        cerr << "OKVS encoding failed" << endl;
        return false;
    }
    cout << "OKVS encoding completed in " << ms << " ms" << endl;
    
    // Step 3: Distribute to servers
    if (!distributeToServers(encryptionKey, okvs, server1, port1, server2, port2)) {
        cerr << "Failed to distribute data to servers" << endl;
        return false;
    }
    
    return true;
}

// --- helper: receive and decode from servers (test function) ---
bool receiveFromServers(
    uint16_t keyPort,
    uint16_t okvsPort,
    std::vector<unsigned char>& encryptionKey,
    oc::Matrix<block>& okvs)
{
    cout << "\n=== Receiving data from servers ===" << endl;
    
    try {
        // Start server 1 for encryption key
        cout << "Starting server on port " << keyPort << " for encryption key..." << endl;
        SocketServer keyServer(keyPort);
        if (!keyServer.start()) {
            cerr << "Failed to start key server" << endl;
            return false;
        }
        
        cout << "Waiting for key connection..." << endl;
        if (!keyServer.acceptConnection()) {
            cerr << "Failed to accept key connection" << endl;
            return false;
        }
        
        cout << "Receiving encryption key..." << endl;
        encryptionKey = keyServer.receiveWithLength();
        if (encryptionKey.empty()) {
            cerr << "Failed to receive encryption key" << endl;
            return false;
        }
        cout << "Encryption key received: " << encryptionKey.size() << " bytes" << endl;
        keyServer.stop();
        
        // Start server 2 for OKVS matrix
        cout << "\nStarting server on port " << okvsPort << " for OKVS matrix..." << endl;
        SocketServer okvsServer(okvsPort);
        if (!okvsServer.start()) {
            cerr << "Failed to start OKVS server" << endl;
            return false;
        }
        
        cout << "Waiting for OKVS connection..." << endl;
        if (!okvsServer.acceptConnection()) {
            cerr << "Failed to accept OKVS connection" << endl;
            return false;
        }
        
        cout << "Receiving OKVS matrix..." << endl;
        auto okvsData = okvsServer.receiveWithLength();
        if (okvsData.empty()) {
            cerr << "Failed to receive OKVS matrix" << endl;
            return false;
        }
        cout << "OKVS matrix received: " << okvsData.size() << " bytes" << endl;
        
        okvs = deserializeMatrix(okvsData);
        cout << "OKVS matrix deserialized: " << okvs.rows() << "x" << okvs.cols() << endl;
        okvsServer.stop();
        
        cout << "\n=== Reception completed successfully ===" << endl;
        return true;
        
    } catch (const std::exception& e) {
        cerr << "Reception error: " << e.what() << endl;
        return false;
    }
}

// --- helper: generate and distribute encrypted OKVS ---
void encodeAndDistribute(oc::CLP& cmd)
{
    int bits = cmd.getOr("b", 64);
    auto w = cmd.getOr("w", 3);
    auto ssp = cmd.getOr("ssp", 40);
    auto dt = cmd.isSet("binary") ? PaxosParam::Binary : PaxosParam::GF128;
    
    string keyPath = "../keys.txt";
    string valPath = "../values.txt";
    string server1 = cmd.isSet("server1") ? cmd.get<string>("server1") : "172.24.122.104";
    uint16_t port1 = cmd.getOr("port1", 9001u);
    string server2 = cmd.isSet("server2") ? cmd.get<string>("server2") : "172.24.122.107";
    uint16_t port2 = cmd.getOr("port2", 9002u);
    
    vector<block> keys;
    oc::Matrix<block> vals;
    
    // Load keys and generate values from them
    if (!loadKeysAndGenerateValues(keys, vals, keyPath, valPath)) {
        return;
    }
    
    size_t n = keys.size();
    PaxosParam pp(n, w, ssp, dt);
    
    cout << "Loaded " << n << " key-value pairs" << endl;
    cout << "Target servers: " << server1 << ":" << port1 << " and " << server2 << ":" << port2 << endl;
    
    // Generate encryption key
    cout << "\nGenerating encryption key..." << endl;
    auto encryptionKey = Encryption::generateEncryptionKey();
    cout << "Encryption key generated: " << encryptionKey.size() << " bytes" << endl;
    
    // Encode and distribute
    oc::Matrix<block> okvs;
    if (!encodeWithDistribution(bits, keys, vals, okvs, pp, encryptionKey, server1, port1, server2, port2)) {
        cerr << "Failed to encode and distribute" << endl;
        return;
    }
    
    cout << "\nProcess completed successfully!" << endl;
}

// --- helper: test receiving functionality ---
void receiveAndDecode(oc::CLP& cmd)
{
    uint16_t keyPort = cmd.getOr("kport", 9001u);
    uint16_t okvsPort = cmd.getOr("oport", 9002u);
    
    std::vector<unsigned char> encryptionKey;
    oc::Matrix<block> okvs;
    
    if (!receiveFromServers(keyPort, okvsPort, encryptionKey, okvs)) {
        cerr << "Failed to receive from servers" << endl;
        return;
    }
    
    cout << "\nData successfully received from servers!" << endl;
}

// --- helper: display usage ---
void displayUsage()
{
    cout << "Usage:" << endl;
    cout << "  ./main -paxos           : Run performance benchmark" << endl;
    cout << "  ./main -encode          : Encode key-value pairs into OKVS" << endl;
    cout << "  ./main -decode          : Decode OKVS" << endl;
    cout << "  ./main -distribute      : Generate encrypted OKVS and distribute to servers" << endl;
    cout << "  ./main -receive         : Receive encrypted OKVS from servers" << endl;
    cout << "\nOptions for -distribute:" << endl;
    cout << "  -server1 <ip>           : IP of server 1 (default: 172.24.122.104)" << endl;
    cout << "  -port1 <port>           : Port of server 1 (default: 9001)" << endl;
    cout << "  -server2 <ip>           : IP of server 2 (default: 172.24.122.107)" << endl;
    cout << "  -port2 <port>           : Port of server 2 (default: 9002)" << endl;
    cout << "  -b <bits>               : Bit size (8/16/32/64, default: 64)" << endl;
    cout << "\nOptions for -receive:" << endl;
    cout << "  -kport <port>           : Port for receiving encryption key (default: 9001)" << endl;
    cout << "  -oport <port>           : Port for receiving OKVS (default: 9002)" << endl;
}

// --- main ----------------

int main(int argc, char** argv)
{
    CLP cmd;
    cmd.parse(argc, argv);

    // If user asked for standalone encode/decode, do them first
    if (cmd.isSet("encode") || cmd.isSet("decode")) {
        int bits = cmd.getOr("b", 64);
        auto w = cmd.getOr("w", 3);
        auto ssp = cmd.getOr("ssp", 40);
        auto dt = cmd.isSet("binary") ? PaxosParam::Binary : PaxosParam::GF128;

        string keyPath = "../keys.txt";
        string valPath = "../values.txt";
        string okvsPath = "okvs.bin";

        vector<block> keys;
        oc::Matrix<block> vals;

        // Load keys and generate values from them
        if (!loadKeysAndGenerateValues(keys, vals, keyPath, valPath)) {
            return 1;
        }

        size_t n = keys.size();
        PaxosParam pp(n, w, ssp, dt);

        if (cmd.isSet("encode")) {
            cout << "Running standalone encode (bits=" << bits << ") ..." << endl;
            oc::Matrix<block> okvs;
            auto t0 = chrono::high_resolution_clock::now();
            bool ok = encodeOKVS_dispatch(bits, keys, vals, okvs, pp, 0);
            auto t1 = chrono::high_resolution_clock::now();
            double ms = chrono::duration_cast<chrono::microseconds>(t1 - t0).count() / 1000.0;
            if (ok) {
                cout << "Encode completed in " << ms << " ms. Saving to " << okvsPath << endl;
                if (!saveMatrixToFile(okvs, okvsPath)) {
                    cerr << "Failed to save okvs to " << okvsPath << endl;
                }
            } else {
                cerr << "Encode failed.\n";
                return 1;
            }
            return 0;
        }

        if (cmd.isSet("decode")) {
            cout << "Running standalone decode (bits=" << bits << ") ..." << endl;
            oc::Matrix<block> okvs;
            if (!loadMatrixFromFile(okvs, okvsPath)) {
                cerr << "Failed to load okvs from " << okvsPath << endl;
                return 1;
            }
            oc::Matrix<block> decoded;
            auto t0 = chrono::high_resolution_clock::now();
            bool ok = decodeOKVS_dispatch(bits, keys, okvs, decoded, pp, 0);
            auto t1 = chrono::high_resolution_clock::now();
            double ms = chrono::duration_cast<chrono::microseconds>(t1 - t0).count() / 1000.0;
            if (ok) {
                cout << "Decode completed in " << ms << " ms. Showing first 10 results:\n";
                for (size_t i = 0; i < min<size_t>(10, keys.size()); ++i) {
                    cout << "key[" << i << "] = " << keys[i] << " -> value = " << decoded(i, 0) << "\n";
                }
            } else {
                cerr << "Decode failed.\n";
                return 1;
            }
            return 0;
        }
    }

    // New: Distribution mode
    if (cmd.isSet("distribute")) {
        encodeAndDistribute(cmd);
        return 0;
    }

    // New: Reception mode (for testing)
    if (cmd.isSet("receive")) {
        receiveAndDecode(cmd);
        return 0;
    }

    // Default behavior
    if (cmd.isSet("paxos")) {
        perfPaxos(cmd);
    } else if (!cmd.isSet("distribute") && !cmd.isSet("receive")) {
        displayUsage();
    }

    return 0;
}
