#ifndef FILEUTILS_HPP
#define FILEUTILS_HPP

#include <filesystem>
#include <fstream>

inline bool fileExists(const std::string &filePath) {
    const std::ifstream file(filePath);
    return file.good();
}

inline std::ifstream initFile(const std::string &filePath, const std::string &initContent) {
    // json parser wil not work without an existed json file and the program will terminate.
    if (fileExists(filePath)) {
        return std::ifstream(filePath);
    }

    const std::filesystem::path directory = std::filesystem::path(filePath).parent_path();
    if (!exists(directory)) {
        create_directories(directory);
    }

    std::ofstream file(filePath);
    if (file.is_open()) {
        file << initContent;
        file.close();
    }
    return std::ifstream(filePath);
}

#endif
