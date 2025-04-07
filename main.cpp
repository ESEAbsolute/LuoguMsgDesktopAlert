// Clients
#include "include/client/HTTPClient.hpp"
#include "include/client/WebSocketClient.hpp"

// Modules
#include "include/MsgManager.hpp"

// #warning Please include winsock2.h before windows.h
// Event & Handlers
#include "include/event/ListenersImpl.hpp"

// Other Dependencies
#include <nlohmann/json.hpp>
#include "include/ESEAbs0Misc.hpp"

#include "LocalLogger.hpp"

int uid; // user UID of the client
std::string _uid; // cookie value of _uid of the client (string)
std::string __client_id; // cookie value of __client_id of the client
std::string getCookie() { // full cookie of the client
    return ("__client_id=" + __client_id + "; _uid=" + _uid);
}

const std::string certFile = "ISRG Root X1.crt";
std::string uri = "wss://ws.luogu.com.cn/ws";
const std::string tls_init_handlr = "ws.luogu.com.cn";
nlohmann::json joinMessage;

EventManager eventManager;
NWSConnection::WebSocketClient session;
boolean sessionClosed = false;

class wsEventsImpl : public NWSConnection::wsConnectionEvents {
public:
    void onMessage(const websocketpp::connection_hdl &hdl, const client::message_ptr &msg) override {
        std::string message = msg->get_payload();
        localLogger.log(0, "WSEvent", "Received BROADCAST / Message: " + message);

        const nlohmann::json u = nlohmann::json::parse(message);
        eventManager.fireEvent(new BroadcastEvent(u));
    }
    bool onPing(const websocketpp::connection_hdl &hdl, const std::string &payload) override {
        localLogger.log(0, "WSEvent", "Received PING / Payload: " + payload);

        return true;
    }
} eventsImpl;

inline class heartbeatListener : virtual public BroadcastListener, virtual public UpdateListener {
    int timeRemain = 20 * 96; // heartbeat interval = 90 sec
public:
    void onBroadcast(const nlohmann::json &msg) override {
        if (msg["_ws_type"] == "heartbeat") {
            timeRemain = 20 * 96;
        }
    }
    void onUpdate() override {
        timeRemain--;
        if (timeRemain == 0) {
            sessionClosed = true;
            session.closeConnection(
                    []() { localLogger.log(2, "WSConnection", "Connection closed because heartbeat not received"); },
                    []() { localLogger.log(3, "WSConnection", "Error while closing WebSocket connection"); });
        }
    }
} heartbeatHdl;

inline class logonListener : virtual public BroadcastListener, virtual public UpdateListener {
    int timeRemain = 20 * 5; // 5 sec
public:
    void onBroadcast(const nlohmann::json &msg) override {
        if (msg["_ws_type"] == "join_result") {
            std::cout << "Logged in successfully!" << "\n" << std::endl;
            localLogger.log(1, "Listeners", "Logged in successfully!");

            eventManager.removeEventListener(this, new BroadcastEvent(""));
            eventManager.removeEventListener(this, new UpdateEvent());
        }
    }
    void onUpdate() override {
        timeRemain--;
        if (timeRemain == 0) {
            eventManager.removeEventListener(this, new BroadcastEvent(""));
            eventManager.removeEventListener(this, new UpdateEvent());
            sessionClosed = true;
            session.closeConnection(
                    []() { localLogger.log(2, "WSConnection", "Connection closed due to login failed"); },
                    []() { localLogger.log(3, "WSConnection", "Error while closing WebSocket connection"); });
        }
    }
    void resetTimer() {
        timeRemain = 20 * 5;
    }
} logonHdl;

void readCookies();
void initializeClient();
void initializeTick();
void registerEvents();

void wsClientConnection(NWSConnection::WebSocketClient &session);

signed main(int argc, char *argv[]) {
    if (argc == 2) {
        if (argv[1]) {
            const char *arg = argv[1];
            char *endptr;
            int logLevel = strtol(arg, &endptr, 10);
            if (*endptr == '\0') {
                localLogger.setLogLevel(logLevel);
            }
        }
    }

    readCookies();
    initializeClient();
    initializeTick();
    registerEvents();

    session.setEvents(std::make_shared<wsEventsImpl>());
    const auto customEvents = std::make_shared<wsEventsImpl>();

    std::thread thrWsClient([]() { wsClientConnection(session); });
    thrWsClient.detach();

    while (true) {
        ;
    } // Handling GUI: WIP.
}

void readCookies() {
    std::ifstream inCookie("cookie.txt");
    inCookie >> _uid >> __client_id;
    inCookie.close();

    unsigned int ulen = _uid.length();
    uid = 0;
    for (unsigned int i = 0; i < ulen; i++) {
        uid = uid * 10 + _uid[i] - '0';
    }

    localLogger.log(1, "Main", "Cookies initialized!");
}

void initializeClient() {
    joinMessage = {{"type", "join_channel"}, {"channel", "chat"}, {"channel_param", _uid}, {"exclusive_key", NULL}};
    NHTTPConnection::setCookies(getCookie());

    auto response = NHTTPConnection::getContent("/_lfe/config");
    if (response.success) {
        nlohmann::json u = nlohmann::json::parse(response.body);
        uri = u["ws"]["server"];
    }

    localLogger.log(1, "Main", "Join message initialized!");
}


void initializeTick() {
    std::thread tickThread([]() {
        auto initial = std::chrono::steady_clock::now();
        int counter = 1;
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(now - initial);
            if (elapsed.count() >= 0.05 * counter) {
                eventManager.fireEvent(new UpdateEvent());
                counter++;
            }
        }
    });
    tickThread.detach();
}

void registerEvents() {
    eventManager.addEventListener(&logReceiveHdl, new BroadcastEvent(""));
    eventManager.addEventListener(&heartbeatHdl, new BroadcastEvent(""));
    eventManager.addEventListener(&heartbeatHdl, new UpdateEvent());
    eventManager.addEventListener(&messageHdl, new BroadcastEvent(""));

    localLogger.log(1, "Main", "Events registered!");
}

void wsClientConnection(NWSConnection::WebSocketClient &session) {
    logonHdl.resetTimer();
    eventManager.addEventListener(&logonHdl, new BroadcastEvent(""));
    eventManager.addEventListener(&logonHdl, new UpdateEvent());
    sessionClosed = false;
    session.openConnection(
            uri, tls_init_handlr, joinMessage, getCookie(), certFile,
            []() { localLogger.log(1, "WSConnection", "Connected"); },
            []() { localLogger.log(3, "WSConnection", "Failed to connect"); },
            [](websocketpp::exception const &e) { std::cerr << e.what() << std::endl; });
    if (sessionClosed == false) {
        session.closeConnection(
                []() { localLogger.log(2, "WSConnection", "Connection closed"); },
                []() { localLogger.log(3, "WSConnection", "Error while closing WebSocket connection"); });
    }
    Sleep(1000);
}
