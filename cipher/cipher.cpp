#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>
using namespace CryptoPP;
using namespace std;

SecByteBlock generateKeyFromPassword(const string& password)
{
    SecByteBlock key(AES::MAX_KEYLENGTH);
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
    pbkdf2.DeriveKey(key, key.size(), 0, (CryptoPP::byte*)password.data(), password.size(), (CryptoPP::byte*)password.data(), password.size(), 1000);
    return key;
}
void encryptFile(const string& inputFile, const string& outputFile, const string& password)
{
    SecByteBlock key = generateKeyFromPassword(password);
    SecByteBlock iv(AES::BLOCKSIZE);
    AutoSeededRandomPool prng;
    prng.GenerateBlock(iv, iv.size());
    ofstream encryptedFile(outputFile, ios::binary);
    encryptedFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, key.size(), iv);
    FileSource(inputFile.c_str(), true, new StreamTransformationFilter(encryptor, new FileSink(encryptedFile)));
}
void decryptFile(const string& inputFile, const string& outputFile, const string& password)
{
    SecByteBlock key = generateKeyFromPassword(password);
    SecByteBlock iv(AES::BLOCKSIZE);
    ifstream encryptedFile(inputFile, ios::binary);
    encryptedFile.read(reinterpret_cast<char*>(iv.data()), iv.size());
    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), iv);
    FileSource(encryptedFile, true, new StreamTransformationFilter(decryptor, new FileSink(outputFile.c_str())));
}

int main() {
    std::string mode;
    std::string inputFile;
    std::string outputFile;
    std::string password;
    std::cout << "Выберите операцию (1 - encrypt, 2 - decrypt): ";
    std::cin >> mode;
    std::cout << "Введите исходный файл: ";
    std::cin >> inputFile;
    std::cout << "Введите файл для записи: ";
    std::cin >> outputFile;
    std::cout << "Введите пароль: ";
    std::cin >> password;
    if (mode == "1") {
        encryptFile(inputFile, outputFile, password);
        std::cout << "Файл успешно зашифрован" << std::endl;
    } else if (mode == "2") {
        decryptFile(inputFile, outputFile, password);
        std::cout << "Файл успешно расшифрован" << std::endl;
    } else {
        std::cerr << "Неправильно выбрана операция" << std::endl;
        return 1;
    }
    return 0;
}
