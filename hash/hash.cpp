#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
using namespace std;

string hashFile(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не удалось открыть файл: " + filename);
    }
    CryptoPP::SHA256 hash;
    vector<uint8_t> buffer(1024);
    string digest;
    while (file.good()) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        hash.Update(buffer.data(), file.gcount());
    }
    digest.resize(hash.DigestSize());
    hash.Final(reinterpret_cast<uint8_t*>(&digest[0]));
    string hexDigest;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexDigest));
    encoder.Put(reinterpret_cast<const uint8_t*>(digest.data()), digest.size());
    encoder.MessageEnd();
    return hexDigest;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Использование: " << argv[0] << " <имя_файла>" << endl;
        return 1;
    }
    try {
        string filename = argv[1];
        string hash = hashFile(filename);
        cout << "Хэш SHA-256 для файла " << filename << ": " << hash << endl;
    } catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }
    return 0;
}
