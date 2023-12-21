#include <websocketpp/config/asio_client.hpp>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <websocketpp/client.hpp>
#include <nlohmann/json.hpp>
#include <httplib.h>
#include <iostream>
#include <wchar.h>
#include <ctime>
#include <cmath>

typedef websocketpp::client<websocketpp::config::asio_tls_client> client;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;

client c;
httplib::Client cli("https://cdn.luogu.com.cn");
int uid;
std::string _uid;
std::string __client_id;
clock_t time_req;
clock_t timePing_req;
bool islogon = 0;
bool pingReceived = 1;
client::connection_ptr con;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

void closeConnection ( ) {
  websocketpp::lib::error_code ec;
  con->close(websocketpp::close::status::going_away, "", ec);
  if (ec) {
    std::cout << "> Error closing connection: "  
              << ec.message() << std::endl;
  }
}


void loginChecker ( ) {
  Sleep (1000 * 5);
  if (islogon == 0) {
    std::cout << "The program will terminate without join_result received in 5 seconds." << std::endl;
    closeConnection ( );
  }
}
void pingTimer ( ) { // 54s < 60s
  Sleep (1000 * 60);
  if ((float) (clock ( ) - timePing_req) / CLOCKS_PER_SEC > 60.0) {
    std::cout << "The program will terminate for no ping is received "
    << "for 1 minute (normal value: approx 54 seconds)." << std::endl;
    closeConnection ( );
  }
}
void heartbeatTimer ( ) { // 90s < 96s
  Sleep (1000 * 96);
  if ((float) (clock ( ) - time_req) / CLOCKS_PER_SEC > 96.0) {
    std::cout << "The program will terminate for no heartbeat is received "
    << "for 1.6 minutes (normal value: approx 90 seconds)." << std::endl;
    closeConnection ( );
  }
}


std::string UTF8ToString(const std::string& utf8Str) {
  // std::string utf8Str = "你好，世界！";
  int utf8Size = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str( ), -1, NULL, 0);
  std::wstring utf16Str;
  utf16Str.resize(utf8Size - 1);
  MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str( ), -1, &utf16Str[0], utf8Size);

  int gbkSize = WideCharToMultiByte(CP_ACP, 0, utf16Str.c_str( ), -1, NULL, 0, NULL, NULL);
  std::string gbkStr;
  gbkStr.resize(gbkSize - 1);
  WideCharToMultiByte(CP_ACP, 0, utf16Str.c_str( ), -1, &gbkStr[0], gbkSize, NULL, NULL);
  return gbkStr;
}


void NotifyNodeJS (std::string Message, std::string Sender, std::string SenderUID) {
  std::string appNameParam = "--appName=\"洛谷私信提醒\" ";
  std::string titleParam = "--title=\"来自 " + Sender + " 的洛谷私信\" ";
  std::string contentParam = "--content=\"" + Message + "\" ";
  appNameParam = UTF8ToString (appNameParam);
  titleParam = UTF8ToString (titleParam);
  contentParam = UTF8ToString (contentParam);
  Sender = UTF8ToString (Sender);
  Message = UTF8ToString (Message);
  std::cout << "Sender = " << Sender << "(" << SenderUID << "); ";
  std::cout << "Message = " << Message << ";" << std::endl;
  std::string iconParam = "--icon=\"./cache/" +  SenderUID + ".png\" ";
  std::string triggerParam = "--trigger=\"https://www.luogu.com.cn/chat?uid=" + SenderUID + "\" ";
  std::string command = "\"\"./NotifierNodeJS.exe\" " + appNameParam
                      + titleParam + contentParam + iconParam + triggerParam + "\"";
  std::cout << "COMMAND = " << command << std::endl;
  system (command.c_str( ));
}


// Verify that one of the subject alternative names matches the given hostname
bool verify_subject_alternative_name(const char* hostname, X509* cert) {
  STACK_OF(GENERAL_NAME)* san_names = NULL;
  san_names = (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
  if (san_names == NULL) { return false; }
  int san_names_count = sk_GENERAL_NAME_num(san_names);
  bool result = false;
  for (int i = 0; i < san_names_count; i++) {
    const GENERAL_NAME* current_name = sk_GENERAL_NAME_value(san_names, i);
    if (current_name->type != GEN_DNS) { continue; }
    char const* dns_name = (char const*)ASN1_STRING_get0_data(current_name->d.dNSName);
    if (ASN1_STRING_length(current_name->d.dNSName) != (int) strlen(dns_name)) { break; }
    result = (strcasecmp(hostname, dns_name) == 0);
  }
  sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
  return result;
}


bool verify_common_name(char const* hostname, X509* cert) {
  int common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(cert), NID_commonName, -1);
  if (common_name_loc < 0) { return false; }
  X509_NAME_ENTRY* common_name_entry = X509_NAME_get_entry(X509_get_subject_name(cert), common_name_loc);
  if (common_name_entry == NULL) { return false; }
  ASN1_STRING* common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
  if (common_name_asn1 == NULL) { return false; }
  char const* common_name_str = (char const*)ASN1_STRING_get0_data(common_name_asn1);
  if (ASN1_STRING_length(common_name_asn1) != (int) strlen(common_name_str)) { return false; }
  return (strcasecmp(hostname, common_name_str) == 0);
}


bool verify_certificate(const char* hostname, bool preverified, boost::asio::ssl::verify_context& ctx) {
  int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle( ));
  if (depth == 0 && preverified) {
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle( ));
    if (verify_subject_alternative_name(hostname, cert)) { return true; }
    else if (verify_common_name(hostname, cert)) { return true; }
    else { return false; }
  }
  return preverified;
}


std::string cert = "ISRG Root X1.crt";
context_ptr on_tls_init(const char* hostname, websocketpp::connection_hdl) {
  context_ptr ctx = websocketpp::lib::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::sslv23);
  try {
    ctx->set_options(boost::asio::ssl::context::default_workarounds |
      boost::asio::ssl::context::no_sslv2 |
      boost::asio::ssl::context::no_sslv3 |
      boost::asio::ssl::context::single_dh_use);
    ctx->set_verify_mode(boost::asio::ssl::verify_peer);
    ctx->set_verify_callback(bind(&verify_certificate, hostname, ::_1, ::_2));
    ctx->load_verify_file(cert.c_str( ));
  }
  catch (std::exception& e) { std::cout << e.what( ) << std::endl; }
  return ctx;
}


void getAvatar (std::string userid) {
  std::ifstream in("./cache/cache.json");
  nlohmann::json infile = nlohmann::json::parse(in);
  in.close( );
  if (!infile[userid].is_null( )) {
    int usrID = infile[userid];
    if ((int)time(0) - usrID < 3600) {
      return;
    }
  }
  std::string req = "/upload/usericon/" + userid + ".png";
  if (auto res = cli.Get(req)) {
    if (res->status == 200) {
      std::string outpic = "./cache/" + userid + ".png";
      std::ofstream outfile(outpic.c_str( ), std::ofstream::binary);
      outfile.write(res->body.c_str( ), res->body.size( ));
      outfile.close( );
      std::cout << " Image downloaded successfully.\n";
      infile[userid] = time(0);
      std::ofstream out("./cache/cache.json");
      out << std::setw(4) << infile << std::endl;
      out.close( );
    } else {
      std::cout << res->status << std::endl;
    }
  } else {
    auto err = res.error();
    std::cout << "HTTP error: " << httplib::to_string(err) << std::endl;
  }
}


bool on_ping(client* c, websocketpp::connection_hdl hdl, std::string payload) {
  std::cout << "Received Ping" << payload << std::endl <<
  "The interval since the last ping is " <<
  (float) (clock ( ) - timePing_req) / CLOCKS_PER_SEC << " seconds." << std::endl;
  timePing_req = clock ( );
  std::thread thrPing(pingTimer);
  thrPing.detach ( );
  return true;
}
void on_pong(client* c, websocketpp::connection_hdl hdl, std::string payload) {
  std::cout << "Received Pong: " << payload << std::endl;
}


void on_message(websocketpp::connection_hdl hdl, client::message_ptr msg) {
  std::string message = msg->get_payload( );
  std::cout << "Received message: " << std::endl;
  std::cout << message.c_str( ) << std::endl;

  nlohmann::json u = nlohmann::json::parse(message);

  if (u["_ws_type"] == "server_broadcast" && u["message"]["receiver"]["uid"] == uid) {
    std::cout << "Getting avatar of " << u["message"]["sender"]["name"] << "(" 
              << u["message"]["sender"]["uid"] << ") ......" << std::endl;
    getAvatar (std::to_string((int) u["message"]["sender"]["uid"]));
    std::thread Notif(bind(NotifyNodeJS, u["message"]["content"],
        u["message"]["sender"]["name"], std::to_string((int) u["message"]["sender"]["uid"])));
    Notif.detach ( );
  } else if (u["_ws_type"] == "heartbeat") {
    std::cout << "The interval since the last heartbeat is " <<
    (float) (clock ( ) - time_req) / CLOCKS_PER_SEC << " seconds." << std::endl;
    time_req = clock ( );
    std::thread thrHeartbeat(heartbeatTimer);
    thrHeartbeat.detach ( );
  } else if (u["_ws_type"] == "join_result") {
    islogon = 1;
    std::cout << "Login successfully! Timing start!" << std::endl;
    time_req = clock ( );
    std::thread thrHeartbeat(heartbeatTimer);
    thrHeartbeat.detach ( );
  }
}

signed main(int argc, char* argv[]) {
  system("chcp 65001");
  std::string uri = "wss://ws.luogu.com.cn/ws";
  std::string tls_init_handlr = "ws.luogu.com.cn";

  freopen("cookie.txt", "r", stdin);
  std::cin >> _uid >> __client_id;
  int ulen = _uid.length( );
  for (int i = 0; i < ulen; i++) uid = uid * 10 + _uid[i] - '0';
  std::string cookie = "__client_id=" + __client_id + "; _uid=" + _uid;
  cli.set_default_headers({ { "Cookie", cookie } });

  nlohmann::json joinMessage = {
    {"type", "join_channel"},
    {"channel", "chat"},
    {"channel_param", _uid},
    {"exclusive_key", nullptr}
  };
  std::string messageStr = joinMessage.dump( );

  try {
    // Set logging to be pretty verbose (everything except message payloads)
    c.set_access_channels(websocketpp::log::alevel::all);
    c.clear_access_channels(websocketpp::log::alevel::frame_payload);
    c.set_error_channels(websocketpp::log::elevel::all);

    // Initialize ASIO
    c.init_asio( );

    c.set_message_handler(bind(&on_message, ::_1, ::_2));
    c.set_ping_handler(bind(&on_ping, &c, ::_1, ::_2));
    c.set_pong_handler(bind(&on_pong, &c, ::_1, ::_2));
    c.set_tls_init_handler(bind(&on_tls_init, tls_init_handlr.c_str( ), ::_1));

    websocketpp::lib::error_code ec;
    c.set_open_handler([&messageStr](websocketpp::connection_hdl hdl) {
      std::cout << "Connection opened!" << std::endl;
      c.send(hdl, messageStr, websocketpp::frame::opcode::text);
      timePing_req = clock ( );
      
      std::thread thrLogin(loginChecker);
      thrLogin.detach( );
      std::thread thrPing(pingTimer);
      thrPing.detach ( );
    });

    con = c.get_connection(uri, ec);
    if (ec) {
      std::cout << "could not create connection because: " << ec.message( ) << std::endl;
      exit (0);
    }
    con->append_header("Cookie", cookie);
    c.connect(con);
    c.get_alog( ).write(websocketpp::log::alevel::app, "Connecting to " + uri);
    c.run( );
  }
  catch (websocketpp::exception const& e) {
    std::cout << e.what( ) << std::endl;
  }
}
