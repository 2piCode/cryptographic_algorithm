#include <iostream>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <iomanip>

const int NUM_ROUNDS = 32;
const uint32_t DELTA = 0x9e3779b9;
uint32_t key[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};

void encryptTEAblock(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0;
    for(int i = 0; i < NUM_ROUNDS; i++) {
        sum += DELTA;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0;
    v[1] = v1;
}

void decryptTEAblock(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = DELTA * NUM_ROUNDS;
    for(int i = 0; i < NUM_ROUNDS; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= DELTA;
    }
    v[0] = v0;
    v[1] = v1;
}

void printHex(const std::vector<uint8_t>& data) {
    for(auto byte : data)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    std::cout << std::dec << std::endl;
}

std::vector<uint8_t> addPadding(const std::vector<uint8_t>& data) {
    size_t blockSize = 8;
    size_t padding = blockSize - (data.size() % blockSize);
    std::vector<uint8_t> padded = data;
    padded.insert(padded.end(), padding, static_cast<uint8_t>(padding));
    return padded;
}

std::vector<uint8_t> removePadding(const std::vector<uint8_t>& data) {
    if(data.empty()) return data;
    uint8_t padding = data.back();
    if(padding > 8) return data;
    return std::vector<uint8_t>(data.begin(), data.end() - padding);
}

std::vector<std::vector<uint8_t>> splitBlocks(const std::vector<uint8_t>& data, size_t blockSize = 8) {
    std::vector<std::vector<uint8_t>> blocks;
    for(size_t i = 0; i < data.size(); i += blockSize) {
        std::vector<uint8_t> block(data.begin() + i, data.begin() + std::min(data.size(), i + blockSize));
        if(block.size() < blockSize) {
            size_t padding = blockSize - block.size();
            block.insert(block.end(), padding, 0);
        }
        blocks.push_back(block);
    }
    return blocks;
}

std::vector<uint8_t> joinBlocks(const std::vector<std::vector<uint8_t>>& blocks) {
    std::vector<uint8_t> data;
    for(const auto& block : blocks)
        data.insert(data.end(), block.begin(), block.end());
    return data;
}

std::vector<uint8_t> encryptText(const std::string& plaintext, const uint32_t key[4]) {
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());

    data = addPadding(data);

    std::vector<std::vector<uint8_t>> blocks = splitBlocks(data);

    for(auto& block : blocks) {
        uint32_t v[2];
        v[0] = (block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3];
        v[1] = (block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7];

        encryptTEAblock(v, key);

        block[0] = (v[0] >> 24) & 0xFF;
        block[1] = (v[0] >> 16) & 0xFF;
        block[2] = (v[0] >> 8) & 0xFF;
        block[3] = v[0] & 0xFF;
        block[4] = (v[1] >> 24) & 0xFF;
        block[5] = (v[1] >> 16) & 0xFF;
        block[6] = (v[1] >> 8) & 0xFF;
        block[7] = v[1] & 0xFF;
    }

    return joinBlocks(blocks);
}

std::string decryptText(const std::vector<uint8_t>& ciphertext, const uint32_t key[4]) {
    std::vector<std::vector<uint8_t>> blocks = splitBlocks(ciphertext);

    for(auto& block : blocks) {
        uint32_t v[2];
        v[0] = (block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3];
        v[1] = (block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7];

        decryptTEAblock(v, key);

        block[0] = (v[0] >> 24) & 0xFF;
        block[1] = (v[0] >> 16) & 0xFF;
        block[2] = (v[0] >> 8) & 0xFF;
        block[3] = v[0] & 0xFF;
        block[4] = (v[1] >> 24) & 0xFF;
        block[5] = (v[1] >> 16) & 0xFF;
        block[6] = (v[1] >> 8) & 0xFF;
        block[7] = v[1] & 0xFF;
    }

    std::vector<uint8_t> decryptedData = joinBlocks(blocks);

    decryptedData = removePadding(decryptedData);

    return std::string(decryptedData.begin(), decryptedData.end());
}

int main() {
    std::string plaintext;
    std::cout << "Введите текст для шифрования: ";
    std::getline(std::cin, plaintext);

    std::vector<uint8_t> ciphertext = encryptText(plaintext, key);
    std::cout << "Зашифрованный текст (hex): ";
    printHex(ciphertext);

    std::string decryptedText = decryptText(ciphertext, key);
    std::cout << "Расшифрованный текст: " << decryptedText << std::endl;

    return 0;
}
