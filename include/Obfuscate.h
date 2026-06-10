// Obfuscate.h — compile-time XOR string encryption
// String literals are encrypted at compile time; plaintext never appears in binary
#pragma once
#include <string>
#include <cstddef>
#include <array>
#ifdef __linux__
#include <sys/ptrace.h>
#endif

namespace Obf {
    constexpr char KEY = 0xA7;

    template<size_t N>
    struct obfuscated {
        std::array<char, N> data{};

        constexpr obfuscated(const char(&input)[N]) {
            for (size_t i = 0; i < N - 1; i++)
                data[i] = input[i] ^ KEY;
            data[N - 1] = '\0';
        }

        std::string decrypt() const {
            std::string result;
            result.reserve(N - 1);
            for (size_t i = 0; i < N - 1; i++)
                result.push_back(data[i] ^ KEY);
            return result;
        }

        const char* c_str() const {
            return data.data();
        }
    };

    // Anti-debug: returns true if ptrace indicates a debugger
    inline bool detect_debugger() {
#ifdef __linux__
        long ret = ptrace(PTRACE_TRACEME, 0, 0, 0);
        if (ret == -1) return true;
        return false;
#else
        return false;
#endif
    }

    // Runtime string encryption/decryption
    inline std::string encrypt_runtime(const std::string& input, char key = KEY) {
        std::string result = input;
        for (size_t i = 0; i < result.size(); i++)
            result[i] ^= key;
        return result;
    }

    inline std::string decrypt_runtime(const std::string& input, char key = KEY) {
        return encrypt_runtime(input, key);
    }
}

#define OBF(str) (Obf::obfuscated<sizeof(str)>(str))
