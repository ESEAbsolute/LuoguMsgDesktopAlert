#ifndef LISTENERSIMPL_HPP
#define LISTENERSIMPL_HPP

#pragma once

#include "../ESEAbs0Misc.hpp"
#include "LocalLogger.hpp"
#include "handler/EventManager.hpp"

#include "IBroadcastListener.hpp"
using namespace IBroadcastListener;
#include "IUpdateListener.hpp"
using namespace IUpdateListener;


inline class messageListener : virtual public BroadcastListener {
public:
    void onBroadcast(const nlohmann::json &msg) override {
        if (msg["_ws_type"] != "server_broadcast")
            return;
        std::string sender = std::string(msg["message"]["sender"]["name"]) + "(" + std::to_string(static_cast<int>(msg["message"]["sender"]["uid"])) + ")";
        std::cout << std::right << std::setw(30) << sender;
        std::cout << " > " << msg["message"]["content"] << std::endl;
        std::thread Notifu([msg]() {
            int senderUID = msg["message"]["sender"]["uid"];
            std::string senderName = msg["message"]["sender"]["name"];
            std::string msgContent = msg["message"]["content"];
            std::string senderUIDStringified = std::to_string(senderUID);
            NHTTPConnection::getAvatar(senderUIDStringified);
            return NotifyNodeJS("Luogu Message Notifier", "A message from " + senderName, msgContent,
                                "./cache/" + senderUIDStringified + ".png",
                                "https://www.luogu.com.cn/chat?uid=" + senderUIDStringified);
        });
        Notifu.detach();
    }
} messageHdl;

inline class wsBroadcastListener : virtual public BroadcastListener {
public:
    void onBroadcast(const nlohmann::json &msg) override {
        localLogger.log(0, "Listeners", "Received message type: " + std::string(msg["_ws_type"]));
    }
} logReceiveHdl;

#endif // LISTENERSIMPL_HPP
