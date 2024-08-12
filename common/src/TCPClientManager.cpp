#include "TCPClientManager.hpp"
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <iomanip>
#include <cstring>
#include <iostream>
#include <sstream>



using boost::asio::ip::tcp;
using std::placeholders::_1;
using std::placeholders::_2;


template<typename T>
std::istream &operator>>(std::istream& is, std::shared_ptr<T>& item)
{ 
    return item->save(is);
}

template<typename T>
std::ostream &operator<<(std::ostream& os, std::shared_ptr<T>& item)
{
    return item->load(os);
}

TCPClientManager::TCPClientManager(const std::string& server, 
                                   const std::string& port, 
                                   const std::string& pem_file,
                                   std::shared_ptr<StreamableBase> stream_value, 
                                   const int64_t reconnect_timeout)
    : m_io_context(), 
      m_resolver(m_io_context), 
      m_endpoints(m_resolver.resolve(server, port)), 
      m_ssl_context(boost::asio::ssl::context::tlsv13),
      m_socket(),
      m_reconnect_timer(m_io_context),
      m_verified_subjects(),
      m_inbound_data(),
      m_outbound_data(),
      m_outbound_header(),
      m_stream_value(stream_value),
      m_inbound_header(),
      m_reconnect_timeout(reconnect_timeout)
{
    m_ssl_context.load_verify_file(pem_file);
    createSocket(); 
    connect();
}

TCPClientManager::~TCPClientManager()
{}

bool TCPClientManager::verifyCerticate(bool preverified, boost::asio::ssl::verify_context& ctx)
{
    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
    m_verified_subjects.push_back(subject_name);
    return preverified; 
}

void TCPClientManager::createSocket()
{
    m_socket.reset(new boost::asio::ssl::stream<tcp::socket>(m_io_context, m_ssl_context));
    m_socket->set_verify_mode(boost::asio::ssl::verify_peer);
    m_socket->set_verify_callback(std::bind(&TCPClientManager::verifyCerticate, this, _1, _2));
}


bool TCPClientManager::closeSocket()
{
    boost::system::error_code error_code;
    if(m_socket->lowest_layer().close(error_code))
    {
        BOOST_LOG_TRIVIAL(error) << "Close Socket Error (error_code): " << error_code.message();
        return false;
    }
    return true; 
}

bool TCPClientManager::shutdownSocket()
{
    boost::system::error_code error_code;
    if(!m_socket->shutdown(error_code))
    {
        BOOST_LOG_TRIVIAL(error) << "ShutdownSocket Error (error_code): " << error_code.message();
        return false;
    }
    return true;
}

bool TCPClientManager::stopSocket()
{
    boost::system::error_code error_code;
    if(m_socket->lowest_layer().cancel(error_code))
    {
        BOOST_LOG_TRIVIAL(error) << "StopSocket Error (error_code): " << error_code.message();
        return false;
    }
    return true;
}

void TCPClientManager::handshake()
{
    m_socket->async_handshake(boost::asio::ssl::stream_base::client, 
                            [this](const boost::system::error_code& error_code)
    {
        if(!error_code)
        {
            BOOST_LOG_TRIVIAL(info) << "Connected";
            asyncRead();
        }
        else
            BOOST_LOG_TRIVIAL(error) << "Handshake Error (error_code): " << error_code.message();
    });
}

void TCPClientManager::reconnect()
{
    BOOST_LOG_TRIVIAL(info) << "Reconnecting";

    if(!stopSocket() || !shutdownSocket() || !closeSocket())
        BOOST_LOG_TRIVIAL(error) << "Reconnect Error";
    else
    {
        createSocket();
        connect();
    }
}

bool TCPClientManager::isDisconnected(const boost::system::error_code& error_code)
{
    switch(error_code.value())
    {
        case boost::asio::error::connection_reset:
        case boost::asio::error::network_down:
        case boost::asio::error::network_unreachable:
        case boost::asio::error::host_unreachable:
        case boost::asio::error::not_connected:
        case boost::asio::error::no_permission: // most likely stream trunucated, which most likely means the connection was reset during a write/read
            return true;
        default:
            return false;
    }
}

void TCPClientManager::connect()
{
    boost::asio::async_connect(m_socket->lowest_layer(),
                                m_endpoints,
                                [this](const boost::system::error_code& error_code,const tcp::endpoint& /*endpoint*/)
    {
        if(!error_code)
        {
            handshake();
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Connect Error (error_code): " << error_code.message();

            // check if the error is recoverable
            if(error_code.value() != boost::asio::error::connection_refused)
            {
                // log as critical error and return
                BOOST_LOG_TRIVIAL(error) << "Connect Error (error_code): " << error_code.message();
                return;
            }
            if(!closeSocket())
                return;

            if(m_reconnect_timeout > 0)
            {
                m_reconnect_timer.expires_after(boost::asio::chrono::seconds{m_reconnect_timeout});
                m_reconnect_timer.async_wait([this](const boost::system::error_code& error_code)
                {
                    if(!error_code)
                    {
                        connect(); 
                    }
                    else
                    {
                        if(error_code.value() == boost::asio::error::operation_aborted) // The timer could be canceled.
                            connect(); 
                        else
                            BOOST_LOG_TRIVIAL(error) << "Connect Error async_await?? (error_code): " << error_code.message(); 
                    }
                });
            }
                
        }
    });
}

void TCPClientManager::asyncWrite()
{
    std::ostringstream output_sstream, header_stream; 
    std::vector<boost::asio::const_buffer> buffers;

    // load serialized data 
    output_sstream << m_stream_value;
    m_outbound_data = output_sstream.str();
    // load the header string
    const auto outbound_data_size = m_outbound_data.size();
    header_stream << std::setw(sizeof(m_inbound_header)) << std::hex << outbound_data_size;
    m_outbound_header = header_stream.str();

    buffers.push_back(boost::asio::buffer(m_outbound_header));
    if(outbound_data_size != 0) // don't send an empty buffer
        buffers.push_back(boost::asio::buffer(m_outbound_data));

    boost::asio::async_write(*m_socket, buffers,
                            [this](const boost::system::error_code& error_code, size_t length)
    {
        if(!error_code)
        {
            BOOST_LOG_TRIVIAL(debug) << "Successfully wrote " << length << " bytes to the server";
            asyncRead();
        }
        else 
        {
            if(isDisconnected(error_code))
                reconnect();
            else 
                BOOST_LOG_TRIVIAL(error) << "AsyncWrite Error (error_code): " << error_code.message();
        }
    });
}

void TCPClientManager::asyncProcessRead()
{
    std::string archive_string(&m_inbound_data[0], m_inbound_data.size());
    std::istringstream archive_isstream(archive_string);
    archive_isstream >> m_stream_value;
    asyncWrite(); 
}

void TCPClientManager::asyncReadHeader()
{
    std::istringstream is(std::string(m_inbound_header, sizeof(m_inbound_header)));
    uint64_t inbound_data_size = 0; 
    if(!(is >> std::hex >> inbound_data_size))
    {
        BOOST_LOG_TRIVIAL(error) << "AsyncReadData Invalid Argument (inbound_data_size) " << inbound_data_size;
        return;
    }

    if(inbound_data_size == 0)  // nothing to read
        asyncWrite();
    else
    {
        m_inbound_data.resize(inbound_data_size);
        boost::asio::async_read(*m_socket,
                                    boost::asio::buffer(m_inbound_data),
                                    [this](const boost::system::error_code& error_code, size_t length)
        {
            if(!error_code)
            {
                BOOST_LOG_TRIVIAL(debug) << "Successfully read " << length << " bytes from the server";
                asyncProcessRead();
            }
            else 
            {
                if(isDisconnected(error_code))
                    reconnect();
                else
                    BOOST_LOG_TRIVIAL(error) << "AsyncReadData Error (error_code): " << error_code.message();
            }
        });      
    }    
}

void TCPClientManager::asyncRead()
{
    boost::asio::async_read(*m_socket, 
                            boost::asio::buffer(m_inbound_header), 
                            [this](const boost::system::error_code& error_code, size_t /*length*/)
    {
        if(!error_code)
        {
            asyncReadHeader();
        }
        else 
        {
            if(isDisconnected(error_code))
                reconnect();
            else
                BOOST_LOG_TRIVIAL(error) << "AsyncRead Error (error_code): " << error_code.message();
                
        }
    });
}


void TCPClientManager::run()
{
    m_io_context.run();
}
