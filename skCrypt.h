#pragma once
#include <cstring>
#include <cstdint>
#include <random>

// ������� ���������� CRC32 ��� �������� ����������� (��������� ��� ����)
static uint32_t ComputeCRC32(const char* data, size_t size) {
    uint32_t crc = 0xFFFFFFFF;
    const uint32_t polynomial = 0xEDB88320;

    for (size_t i = 0; i < size; i++) {
        crc ^= static_cast<uint8_t>(data[i]);
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ ((crc & 1) ? polynomial : 0);
        }
    }
    return ~crc;
}

// ��������� ����� �� ������ __COUNTER__, __LINE__ � __TIME__ (����� ������� ����)
static uint32_t GenerateKey() {
    const char* time = __TIME__; // ������: "HH:MM:SS"
    uint32_t key = 0;

    // ����������� __COUNTER__ � __LINE__ ��� ������������
    key ^= static_cast<uint32_t>(__COUNTER__ << 16);
    key ^= static_cast<uint32_t>(__LINE__ << 8);

    // ��������� __TIME__ ��� �������������� �������������
    for (int i = 0; time[i] != '\0'; i++) {
        key ^= static_cast<uint8_t>(time[i]) << (i % 24);
    }

    // ����������, ��� ���� �� ����� 0
    return key ? key : 0xDEADBEEF;
}

// ������ ��� ���������� (��������� ���������� ���� ��� ������ ������)
#define skCrypt(str) skCrypt_key(str, GenerateKey() ^ __COUNTER__)
#define skCrypt_key(str, key) []() { \
    auto crypted = skCrypt_impl(str, key); \
    return crypted; \
}().decrypt()

class skCrypt_impl {
public:
    skCrypt_impl(const char* str, uint32_t key) : _size(strlen(str)), _key(key) {
        if (_size >= sizeof(_buffer) - 1) {
            _size = sizeof(_buffer) - 2; // ������������ ������, ����� �������� ������������
        }

        // �������� ������ � �����
        for (size_t i = 0; i < _size; ++i) {
            _buffer[i] = str[i];
        }
        _buffer[_size] = '\0';

        // ���������� ���� �� ������ ����� � ���������� ��������
        std::random_device rd;
        std::mt19937 gen(rd() ^ key);
        _salt = gen() ^ (key << 16);

        // ��������� CRC32 �������� ������
        _crc32 = ComputeCRC32(str, _size);

        // ������� ������
        encrypt();
    }

    const char* decrypt() {
        // ��������������
        for (size_t i = 0; i < _size; ++i) {
            uint8_t byte = static_cast<uint8_t>(_buffer[i]);

            // ���������������� ��������������
            byte ^= (_key >> (i % 32)) ^ (_salt >> (i % 32)); // XOR � ������ � �����
            byte = (byte ^ 0x5A) + (i % 0xFF); // �������������� XOR � ��������
            byte = (byte >> 4) | (byte << 4); // ��������� ������
            byte ^= (_key & 0xFF) ^ (i % 0xFF); // ��� ���� XOR � ������ �����

            _buffer[i] = static_cast<char>(byte);
        }

        // ��������� �����������
        uint32_t currentCRC = ComputeCRC32(_buffer, _size);
        if (currentCRC != _crc32) {
            _buffer[0] = '\0';
            _size = 0;
            return _buffer;
        }

        // ��������� "��������" ������ � ����� ����� ������, ����� ���������� ������ ������
        for (size_t i = _size + 1; i < sizeof(_buffer); ++i) {
            _buffer[i] = static_cast<char>((_key ^ i) & 0xFF);
        }

        return _buffer;
    }

    ~skCrypt_impl() {
        // ������� ������ ����� ���������
        volatile char* p = _buffer;
        for (size_t i = 0; i < sizeof(_buffer); ++i) {
            p[i] = 0;
        }
        _size = 0;
        _salt = 0;
        _crc32 = 0;
        _key = 0;
    }

private:
    void encrypt() {
        // �������
        for (size_t i = 0; i < _size; ++i) {
            uint8_t byte = static_cast<uint8_t>(_buffer[i]);

            // ���������������� �������������� (� �������� �������)
            byte ^= (_key & 0xFF) ^ (i % 0xFF); // XOR � ������ �����
            byte = (byte >> 4) | (byte << 4); // ��������� ������
            byte = (byte - (i % 0xFF)) ^ 0x5A; // �������� � �������������� XOR
            byte ^= (_key >> (i % 32)) ^ (_salt >> (i % 32)); // XOR � ������ � �����

            _buffer[i] = static_cast<char>(byte);
        }

        // ��������� "��������" ������ � ����� ����� ������
        for (size_t i = _size + 1; i < sizeof(_buffer); ++i) {
            _buffer[i] = static_cast<char>((_key ^ i) & 0xFF);
        }
    }

    char _buffer[256]; // ��������� ������ ������
    size_t _size;
    uint32_t _key; // ����������� ������ ����� �� 32 ���
    uint32_t _salt; // ���� ��� ���������� �������
    uint32_t _crc32; // CRC32 ��� �������� �����������
};