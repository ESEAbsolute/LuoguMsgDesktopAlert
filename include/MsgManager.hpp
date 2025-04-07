#ifndef MSGMANAGER_H
#define MSGMANAGER_H

#pragma once

#include <iostream>
#include <vector>

namespace msgManager {
    class message {
    private:
        int senderUID;
        std::string sender;
        std::string msgContent;
        int timestamp;

    public:
        message(const int uid, const std::string &sender, const std::string &content, const int tstamp) {
            this->senderUID = uid;
            this->sender = sender;
            this->msgContent = content;
            this->timestamp = tstamp;
        }
        [[nodiscard]] int getUID() const { return senderUID; }
        std::string getContent() { return msgContent; }
    };


    class msgManager {
    public:
        void onMessage(const int uid, const std::string& sender, const std::string &content, const int tstamp) {
            msgDB.emplace_back(uid, sender, content, tstamp);
        }

        std::vector<message> filterMsg(int uid) {
            std::vector<message> filteredMessages;
            for (auto &msg: msgDB) {
                if (msg.getUID() == uid) {
                    filteredMessages.push_back(msg);
                }
            }
            return filteredMessages;
        }

    private:
        std::vector<message> msgDB;
    };
} // namespace msgManager

#endif
