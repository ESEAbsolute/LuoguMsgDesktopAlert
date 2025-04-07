#ifndef WSCLIENT_H
#define WSCLIENT_H

#pragma once

#include <functional>
#include <utility>
#include <websocketpp/client.hpp>
#include <websocketpp/config/asio_client.hpp>

#include <nlohmann/json.hpp>

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;

typedef websocketpp::client<websocketpp::config::asio_tls_client> client;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;

namespace TLS_INIT {
    // This namespace is derived from examples and documentations.
    // https://github.com/zaphoyd/websocketpp/issues/706
    // https://github.com/cotomonaga/websocketpp_tutorial/blob/master/utility_client/step7.cpp
    // https://blog.csdn.net/byxdaz/article/details/84645586

    inline bool verify_subject_alternative_name(const char *hostname, const X509 *cert) {
        STACK_OF(GENERAL_NAME) *san_names = nullptr;
        san_names = static_cast<struct stack_st_GENERAL_NAME *>(
                X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
        if (san_names == nullptr) {
            return false;
        }
        int san_names_count = sk_GENERAL_NAME_num(san_names);
        bool result = false;
        for (int i = 0; i < san_names_count; i++) {
            const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);
            if (current_name->type != GEN_DNS) {
                continue;
            }
            auto dns_name = reinterpret_cast<char const *>(ASN1_STRING_get0_data(current_name->d.dNSName));
            if (ASN1_STRING_length(current_name->d.dNSName) != static_cast<int>(strlen(dns_name))) {
                break;
            }

            std::string str1(hostname);
            std::string str2(dns_name);

            std::transform(str1.begin(), str1.end(), str1.begin(), ::tolower);
            std::transform(str2.begin(), str2.end(), str2.begin(), ::tolower);

            return (str1 == str2);
        }
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
        return result;
    }

    inline bool verify_common_name(char const *hostname, const X509 *cert) {
        const int common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(cert), NID_commonName, -1);
        if (common_name_loc < 0) {
            return false;
        }
        const X509_NAME_ENTRY *common_name_entry = X509_NAME_get_entry(X509_get_subject_name(cert), common_name_loc);
        if (common_name_entry == nullptr) {
            return false;
        }
        ASN1_STRING *common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
        if (common_name_asn1 == nullptr) {
            return false;
        }
        const auto common_name_str = reinterpret_cast<char const *>(ASN1_STRING_get0_data(common_name_asn1));
        if (ASN1_STRING_length(common_name_asn1) != static_cast<int>(strlen(common_name_str))) {
            return false;
        }

        std::string str1(hostname);
        std::string str2(common_name_str);

        std::transform(str1.begin(), str1.end(), str1.begin(), ::tolower);
        std::transform(str2.begin(), str2.end(), str2.begin(), ::tolower);

        return (str1 == str2);
    }
    inline bool verify_certificate(const char *hostname, bool preverified, boost::asio::ssl::verify_context &ctx) {
        const int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle());
        if (depth == 0 && preverified) {
            X509 *cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
            if (verify_subject_alternative_name(hostname, cert)) {
                return true;
            }
            if (verify_common_name(hostname, cert)) {
                return true;
            }
            return false;
        }
        return preverified;
    }
    inline context_ptr on_tls_init(const char *hostname, const websocketpp::connection_hdl &,
                                   const std::string &certname) {
        context_ptr ctx = websocketpp::lib::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::sslv23);
        try {
            ctx->set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 |
                             boost::asio::ssl::context::no_sslv3 | boost::asio::ssl::context::single_dh_use);
            ctx->set_verify_mode(boost::asio::ssl::verify_peer);
            ctx->set_verify_callback([hostname](auto &&PH1, auto &&PH2) {
                return verify_certificate(hostname, std::forward<decltype(PH1)>(PH1), std::forward<decltype(PH2)>(PH2));
            });
            ctx->load_verify_file(certname);
        } catch (std::exception &e) {

            localLogger.log(3, "WebSocket", "An error occurs while initializing TLS: " + std::string(e.what()));
        }
        return ctx;
    }
} // namespace TLS_INIT

namespace NWSConnection {
    inline client::connection_ptr *conptr = nullptr;

    class wsConnectionEvents {
    public:
        virtual ~wsConnectionEvents() = default;
        virtual void onMessage(const websocketpp::connection_hdl &hdl, const client::message_ptr &msg) {
            localLogger.log(
                    2, "WebSocket",
                    "Default implementation of wsConnectionEvents::onMessage. Check if overrides successfully.");
        }
        virtual bool onPing(const websocketpp::connection_hdl &hdl, const std::string &payload) {
            localLogger.log(2, "WebSocket",
                            "Default implementation of wsConnectionEvents::onPing. Check if overrides successfully.");
            return true;
        }
    };

    class WebSocketClient {
        client c;
        client::connection_ptr con;
        std::shared_ptr<wsConnectionEvents> events;

    public:
        WebSocketClient() : events(std::make_shared<wsConnectionEvents>()) {}
        void setEvents(const std::shared_ptr<wsConnectionEvents> &customEvents) { events = customEvents; }

        void closeConnection(const std::function<void()> &onCloseCallback,
                             const std::function<void()> &onErrorCallback) {
            onCloseCallback();
            websocketpp::lib::error_code ec;
            (*conptr)->close(websocketpp::close::status::going_away, "", ec);

            if (ec) {
                onErrorCallback();
            }
        }

        void openConnection(const std::string &uri, const std::string &tlsInitHandler,
                            const nlohmann::json &joinMessage, const std::string &cookie, const std::string &certname,
                            const std::function<void()> &onConnectCallback,
                            const std::function<void()> &onConnectFailedCallback,
                            const std::function<void(websocketpp::exception const &)> &onExceptionCallback) {
            conptr = &con;
            try {
                // channels
                // c.set_access_channels(websocketpp::log::alevel::all);
                // c.clear_access_channels(websocketpp::log::alevel::frame_header);
                // c.clear_access_channels(websocketpp::log::alevel::frame_payload);
                c.clear_access_channels(websocketpp::log::alevel::all);
                c.set_error_channels(websocketpp::log::elevel::all);

                c.init_asio();
                localLogger.log(0, "WebSocket", "Connection step 1/4: asio initialized");

                // handlers
                c.set_message_handler(bind(&wsConnectionEvents::onMessage, events.get(), ::_1, ::_2));
                c.set_ping_handler(bind(&wsConnectionEvents::onPing, events.get(), ::_1, ::_2));
                c.set_tls_init_handler(bind(&TLS_INIT::on_tls_init, tlsInitHandler.c_str(), ::_1, certname));
                c.set_open_handler([joinMessage, this, onConnectCallback](websocketpp::connection_hdl hdl) {
                    c.send(std::move(hdl), joinMessage.dump(), websocketpp::frame::opcode::text);
                    onConnectCallback();
                });
                localLogger.log(0, "WebSocket", "Connection step 2/4: registered handlers");

                websocketpp::lib::error_code ec;
                con = c.get_connection(uri, ec);
                if (ec) {
                    onConnectFailedCallback();
                }

                con->append_header("Cookie", cookie);
                localLogger.log(0, "WebSocket", "Connection step 3/4: header appended");

                c.connect(con);
                localLogger.log(0, "WebSocket", "Connection step 4/4: connect start");
                c.run();
                // After connection terminated
                c.stop();
                c.reset();
                con.reset();
            } catch (websocketpp::exception const &e) {
                onExceptionCallback(e);
            }
        }
    };
} // namespace NWSConnection

#endif
