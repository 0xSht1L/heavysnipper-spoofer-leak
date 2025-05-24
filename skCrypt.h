#pragma once
#include <cstring>
#include <cstdint>
#include <random>

// Простая реализация CRC32 для проверки целостности (оставляем как есть)
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

// Генерация ключа на основе __COUNTER__, __LINE__ и __TIME__ (более сложный ключ)
static uint32_t GenerateKey() {
    const char* time = __TIME__; // Формат: "HH:MM:SS"
    uint32_t key = 0;

    // Комбинируем __COUNTER__ и __LINE__ для уникальности
    key ^= static_cast<uint32_t>(__COUNTER__ << 16);
    key ^= static_cast<uint32_t>(__LINE__ << 8);

    // Добавляем __TIME__ для дополнительной вариативности
    for (int i = 0; time[i] != '\0'; i++) {
        key ^= static_cast<uint8_t>(time[i]) << (i % 24);
    }

    // Убеждаемся, что ключ не равен 0
    return key ? key : 0xDEADBEEF;
}

// Макрос для шифрования (добавляем уникальный ключ для каждой строки)
#define skCrypt(str) skCrypt_key(str, GenerateKey() ^ __COUNTER__)
#define skCrypt_key(str, key) []() { \
    auto crypted = skCrypt_impl(str, key); \
    return crypted; \
}().decrypt()

class skCrypt_impl {
public:
    skCrypt_impl(const char* str, uint32_t key) : _size(strlen(str)), _key(key) {
        if (_size >= sizeof(_buffer) - 1) {
            _size = sizeof(_buffer) - 2; // Ограничиваем размер, чтобы избежать переполнения
        }

        // Копируем строку в буфер
        for (size_t i = 0; i < _size; ++i) {
            _buffer[i] = str[i];
        }
        _buffer[_size] = '\0';

        // Генерируем соль на основе ключа и случайного значения
        std::random_device rd;
        std::mt19937 gen(rd() ^ key);
        _salt = gen() ^ (key << 16);

        // Вычисляем CRC32 исходной строки
        _crc32 = ComputeCRC32(str, _size);

        // Шифруем строку
        encrypt();
    }

    const char* decrypt() {
        // Расшифровываем
        for (size_t i = 0; i < _size; ++i) {
            uint8_t byte = static_cast<uint8_t>(_buffer[i]);

            // Многоступенчатое преобразование
            byte ^= (_key >> (i % 32)) ^ (_salt >> (i % 32)); // XOR с ключом и солью
            byte = (byte ^ 0x5A) + (i % 0xFF); // Дополнительный XOR и смещение
            byte = (byte >> 4) | (byte << 4); // Побитовые сдвиги
            byte ^= (_key & 0xFF) ^ (i % 0xFF); // Ещё один XOR с частью ключа

            _buffer[i] = static_cast<char>(byte);
        }

        // Проверяем целостность
        uint32_t currentCRC = ComputeCRC32(_buffer, _size);
        if (currentCRC != _crc32) {
            _buffer[0] = '\0';
            _size = 0;
            return _buffer;
        }

        // Добавляем "мусорные" данные в буфер после строки, чтобы затруднить анализ памяти
        for (size_t i = _size + 1; i < sizeof(_buffer); ++i) {
            _buffer[i] = static_cast<char>((_key ^ i) & 0xFF);
        }

        return _buffer;
    }

    ~skCrypt_impl() {
        // Очищаем память более тщательно
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
        // Шифруем
        for (size_t i = 0; i < _size; ++i) {
            uint8_t byte = static_cast<uint8_t>(_buffer[i]);

            // Многоступенчатое преобразование (в обратном порядке)
            byte ^= (_key & 0xFF) ^ (i % 0xFF); // XOR с частью ключа
            byte = (byte >> 4) | (byte << 4); // Побитовые сдвиги
            byte = (byte - (i % 0xFF)) ^ 0x5A; // Смещение и дополнительный XOR
            byte ^= (_key >> (i % 32)) ^ (_salt >> (i % 32)); // XOR с ключом и солью

            _buffer[i] = static_cast<char>(byte);
        }

        // Добавляем "мусорные" данные в буфер после строки
        for (size_t i = _size + 1; i < sizeof(_buffer); ++i) {
            _buffer[i] = static_cast<char>((_key ^ i) & 0xFF);
        }
    }

    char _buffer[256]; // Оставляем размер буфера
    size_t _size;
    uint32_t _key; // Увеличиваем размер ключа до 32 бит
    uint32_t _salt; // Соль для усложнения анализа
    uint32_t _crc32; // CRC32 для проверки целостности
};