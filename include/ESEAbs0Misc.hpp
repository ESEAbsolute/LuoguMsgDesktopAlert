#ifndef ESEABS0MISC_H
#define ESEABS0MISC_H


#include <iostream>
#include <string>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif



inline bool CreateProcessSilent(const std::string &programName, const std::string &cmdArgs) {
#ifdef _WIN32 // Windows implementation

    std::string cmdLine = programName + " " + cmdArgs;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(nullptr, const_cast<char *>(cmdLine.c_str()), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        std::cerr << "CreateProcess failed (" << GetLastError() << ").\n";
        return false;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

#else // POSIX implementation

    pid_t pid = fork();

    if (pid == -1) {
        std::cerr << "Fork failed.\n";
        return false;
    } else if (pid == 0) { // Child process
        std::string cmd = program + " " + args;
        execl("/bin/sh", "sh", "-c", cmd.c_str(), (char *) NULL);
        // If execl returns, it must have failed
        std::cerr << "Exec failed.\n";
        return false; /* exit(1); */
    } else { // Parent process
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            std::cerr << "Child process exited with non-zero status " << WEXITSTATUS(status) << ".\n";
            return false;
        }
    }

#endif

    return true;
}


inline bool NotifyNodeJS(std::string appName, std::string notifTitle, std::string notifContent, std::string notifIcon,
                         std::string openOnClick) {
    std::string commandArgs = fmt::format("--appName=\"{}\" "
                                          "--title=\"{}\" "
                                          "--content=\"{}\" "
                                          "--icon=\"{}\" "
                                          "--trigger=\"{}\" ",
                                          appName, notifTitle, notifContent, notifIcon, openOnClick);
    return CreateProcessSilent("\"./NotifierNodeJS.exe\"", commandArgs);
}

#endif
