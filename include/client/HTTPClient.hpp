#ifndef HTTPCLIENT_HPP
#define HTTPCLIENT_HPP

#pragma once

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "FileUtils.hpp"
#include "LocalLogger.hpp"

namespace NHTTPConnection {
    struct response {
        bool success;
        std::string body;
    };
    
    inline httplib::Client cliFiles("https://cdn.luogu.com.cn");
    inline httplib::Client cliMsg("https://www.luogu.com.cn");
    
    inline void setCookies(const std::string &cookie) {
        cliFiles.set_default_headers({{"Cookie", cookie}});
        cliMsg.set_default_headers({{"Cookie", cookie}, {"referer", "https://www.luogu.com.cn/"}});
    }

    inline response getImpl(httplib::Client cli, const std::string &req) {
        localLogger.log(0, "HTTP Request", "Requesting for " + req);
        if (auto res = cli.Get(req)) {
            if (res->status == 200) {
                return {true, res->body};
            }
            std::string errInfo = std::to_string((int) res->status);
            localLogger.log(3, "HTTP Request", "Failed: HTTP STATUS " + errInfo);
            return {false, errInfo};
        } else {
            auto err = res.error();
            std::string errInfo = httplib::to_string(err);
            localLogger.log(3, "HTTP Request", "HTTP error: " + errInfo);
    
            return {false, errInfo};
        }
    }

    inline response getFile(const std::string &req) { return getImpl(std::move(cliFiles), req); }
    
    inline response getContent(const std::string &req) { return getImpl(std::move(cliMsg), req); }
    
    inline void getAvatar(const std::string &userid) {
        // Read or generate the cache.json
        std::ifstream in = initFile("./cache/cache.json", "{}");
        nlohmann::json infile = nlohmann::json::parse(in);
        in.close();
        // Check if the avatar exists and is valid. Avatar cached for 1 hour
        if (!infile[userid].is_null()) {
            int usrID = infile[userid];
            if (static_cast<int>(time(nullptr)) - usrID < 3600) {
                return;
            }
        }
    
        // Use HTTP GET method to get the avatar. Luogu APIs
        std::string req = "/upload/usericon/" + userid + ".png";
        auto res = getFile(req);
        if (res.success == true) {
            std::string outpic = "./cache/" + userid + ".png";
            std::ofstream outfile(outpic.c_str(), std::ofstream::binary);
            outfile.write(res.body.c_str(), res.body.size());
            outfile.close();
    
            localLogger.log(1, "HTTP Request", "User avatar cached successfully");
    
            infile[userid] = time(nullptr);
            std::ofstream out("./cache/cache.json");
            out << std::setw(4) << infile << std::endl;
            out.close();
        }
    }
} // namespace NHTTPConnection

#endif
