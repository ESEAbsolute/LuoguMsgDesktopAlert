#ifndef LOCALLOGGER_HPP
#define LOCALLOGGER_HPP

#pragma once

#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>

#include "FileUtils.hpp"

namespace NLocalLogger {
    inline std::string getTimestamp(const char *format) {
        const time_t now = time(nullptr);
        tm *timeInfo = localtime(&now);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), format, timeInfo);
        return timestamp;
    }
    inline std::string getLogFileName() {
        std::string currentDate = getTimestamp("%Y-%m-%d");
        int logFileIndex = 1;
        while (true) {
            std::string fullFilePath = "./log/" + currentDate + "-" + std::to_string(logFileIndex) + ".log";
            if (!fileExists(fullFilePath)) {
                initFile(fullFilePath, "Log from "+ getTimestamp("%Y-%m-%d %H:%M:%S") + "\n\n");
                return fullFilePath;
            }
            logFileIndex++;
        }
    }

    enum LogLevel { LDEBUG = 0, LINFO = 1, LWARNING = 2, LERROR = 3, LFATAL = 4, LUNDEFINED = -1 };

    inline LogLevel intToLog(const int levelNum) {
        switch (levelNum) {
            case 0:
                return LDEBUG;
            case 1:
                return LINFO;
            case 2:
                return LWARNING;
            case 3:
                return LERROR;
            case 4:
                return LFATAL;
            default:
                return LUNDEFINED;
        }
    }

    inline class LocalLogger {
    public:
        explicit LocalLogger() : sessionLogLevel(1) { initialized = false; }

        explicit LocalLogger(const std::string &filename, const int &level) {
            sessionLogLevel = level;
            initializeFile(filename);
            initialized = true;
        }

        ~LocalLogger() {
            if (logFile.is_open()) {
                logFile.close();
            }
        }

        void initializeFile(const std::string &filename) {
            std::string fileName = filename;
            if (filename == "auto") {
                fileName = getLogFileName();
                std::cout << "Logging file: " << fileName << std::endl;
            }
            logFileName = fileName;
            logFile.open(logFileName, std::ios::app);
            if (!logFile.is_open()) {
                std::cerr << "Error opening log file." << std::endl;
            }
        }

        void setLogLevel(const int &logLevel) { sessionLogLevel = logLevel; }

        void log(const LogLevel &level, const std::string &logSource, const std::string &message) {
            logImpl(level, logSource, message);
        }

        void log(const int &level, const std::string &logSource, const std::string &message) {
            logImpl(intToLog(level), logSource, message);
        }

    private:
        boolean initialized;
        std::ofstream logFile;
        std::string logFileName;
        int sessionLogLevel;

        static std::string logLevelToString(const LogLevel &level) {
            switch (level) {
                case LDEBUG:
                    return "DEBUG";
                case LINFO:
                    return "INFO";
                case LWARNING:
                    return "WARNING";
                case LERROR:
                    return "ERROR";
                case LFATAL:
                    return "FATAL";
                default:
                    return "UNDEFINED";
            }
        }

        void logImpl(const LogLevel &level, const std::string &logSource, const std::string &message) {
            if (level < sessionLogLevel)
                return;

            std::ostringstream logEntry;
            logEntry << "[" << getTimestamp("%Y-%m-%d %H:%M:%S") << "] ";
            logEntry << "[" << logSource << "/" << logLevelToString(level) << "] ";
            logEntry << message << std::endl;

            if (!logFile.is_open()) {
                logFile.open(logFileName, std::ios::app);
            }
            logFile << logEntry.str();
            logFile.flush();
        }
    } localLogger("auto", 0);
} // namespace NLocalLogger

using NLocalLogger::localLogger;

#endif
