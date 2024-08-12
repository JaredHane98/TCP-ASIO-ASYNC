#ifndef TCPSERVERMANAGER_HPP
#define TCPSERVERMANAGER_HPP

#include <boost/asio/detail/chrono.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio.hpp>
#include "ItemList.hpp"





using boost::asio::ip::tcp;


class TcpSession : public std::enable_shared_from_this<TcpSession>
{
private:
    boost::asio::ssl::stream<tcp::socket> m_socket;
    std::vector<char> m_inbound_data;
    std::string m_outbound_data;
    std::string m_outbound_header; 
    char m_inbound_header[8];
    std::shared_ptr<StreamableBase> m_stream_value;
public:
    TcpSession(boost::asio::ssl::stream<tcp::socket> socket, std::shared_ptr<StreamableBase> stream_value);

    ~TcpSession();

    void start();
private:
    void handshake();

    void asyncProcessRead();

    void asyncReadHeader();

    void asyncRead();

    void asyncWrite();
};

class TcpServerManager
{
private:
    boost::asio::io_context m_io_context;
    boost::asio::ip::tcp::acceptor m_acceptor;
    boost::asio::ssl::context m_ssl_context;
    std::shared_ptr<StreamableBase> m_stream_value;


    std::string getPassword() const;

    void acceptConnections();
public:
    TcpServerManager(const std::string& certif_file, 
                     const std::string& priv_key_file, 
                     const std::string& dh_file,
                     const unsigned short port, 
                     std::shared_ptr<StreamableBase> stream_value);

    ~TcpServerManager();


    TcpServerManager(const TcpServerManager&) = delete;
    TcpServerManager(TcpServerManager&&) = delete;

    void run();
};





#endif // TCPSERVERMANAGER_HPP