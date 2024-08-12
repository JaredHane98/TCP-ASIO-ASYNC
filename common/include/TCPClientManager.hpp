
#ifndef TCPCLIENTMANAGER_HPP
#define TCPCLIENTMANAGER_HPP
#include <boost/asio/detail/chrono.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio.hpp>
#include "ItemList.hpp"



using boost::asio::ip::tcp;

class TCPClientManager
{
private:
    boost::asio::io_context m_io_context;
    tcp::resolver m_resolver;
    tcp::resolver::results_type m_endpoints;
    boost::asio::ssl::context m_ssl_context;
    std::shared_ptr<boost::asio::ssl::stream<tcp::socket>> m_socket;
    boost::asio::steady_timer m_reconnect_timer;
    std::vector<std::string> m_verified_subjects; 
    std::vector<char> m_inbound_data;
    std::string m_outbound_data;
    std::string m_outbound_header;
    std::shared_ptr<StreamableBase> m_stream_value;
    char m_inbound_header[8];
    const int64_t m_reconnect_timeout;

    bool verifyCerticate(bool preverified, boost::asio::ssl::verify_context& ctx);

    void createSocket();

    bool closeSocket();

    bool shutdownSocket();

    bool stopSocket();

    void handshake();

    void reconnect();

    bool isDisconnected(const boost::system::error_code& error_code);

    void connect();

    void asyncWrite();

    void asyncProcessRead();

    void asyncReadHeader();

    void asyncRead();

public:
    TCPClientManager(const std::string& server, 
                     const std::string& port, 
                     const std::string& pem_file,
                     std::shared_ptr<StreamableBase> stream_value, 
                     const int64_t reconnect_timeout = -1);

    ~TCPClientManager();

    void run();
};

#endif // TCPCLIENTMANAGER_HPP