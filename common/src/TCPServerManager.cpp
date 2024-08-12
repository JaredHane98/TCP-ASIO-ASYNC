#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>

#include <memory>
#include <iostream>
#include <iomanip>
#include "TCPServerManager.hpp"


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

TcpSession::TcpSession(boost::asio::ssl::stream<tcp::socket> socket, std::shared_ptr<StreamableBase> stream_value)
        : m_socket(std::move(socket)),
          m_inbound_data(),
          m_outbound_data(),
          m_outbound_header(),
          m_inbound_header(),
          m_stream_value(stream_value)    
{}

TcpSession::~TcpSession()
{
    BOOST_LOG_TRIVIAL(info) << "Connection Closed. Destroying Socket";
}

void TcpSession::start()
{
    handshake();
}

void TcpSession::handshake()
{
    auto self(this->shared_from_this());
    m_socket.async_handshake(boost::asio::ssl::stream_base::server,
                            [this, self](const boost::system::error_code& error_code)
    {
        BOOST_LOG_TRIVIAL(info) << "Handshake with the client";

        if(!error_code)
        {
            asyncWrite();
        }
    });
}

void TcpSession::asyncProcessRead()
{
    std::string archive_string(&m_inbound_data[0], m_inbound_data.size());
    std::istringstream archive_isstream(archive_string);
    archive_isstream >> m_stream_value;
    asyncWrite();
}

void TcpSession::asyncReadHeader()
{
    std::istringstream is(std::string(m_inbound_header, sizeof(m_inbound_header)));
    uint64_t inbound_data_size = 0; 
    if(!(is >> std::hex >> inbound_data_size))
    {
        // maybe want to post the error
        BOOST_LOG_TRIVIAL(error) << "AsyncReadData Invalid Argument (inbound_data_size) " << inbound_data_size;
        return;
    }

    if(inbound_data_size == 0) // nothing to read then proceed to write
        asyncWrite();
    else
    {
        m_inbound_data.resize(inbound_data_size); 
        auto self(this->shared_from_this());
        boost::asio::async_read(m_socket, boost::asio::buffer(m_inbound_data),
                                [this, self](const boost::system::error_code& error_code, size_t length)
        {
            if(!error_code)
            {
                BOOST_LOG_TRIVIAL(debug) << "Successfully read " << length << " bytes from the client";
                asyncProcessRead();
            }
            else 
                BOOST_LOG_TRIVIAL(error) << "AsyncReadData Error (error_code): " << error_code.message();
        });
    }
}

void TcpSession::asyncRead()
{
    auto self(this->shared_from_this());
    boost::asio::async_read(m_socket, boost::asio::buffer(m_inbound_header),
                            [this, self](const boost::system::error_code& error_code, size_t /*length*/)
    {
        if(!error_code)
            asyncReadHeader();
        else
            BOOST_LOG_TRIVIAL(error) << "AsyncRead Error (error_code): " << error_code.message();
    });
}

void TcpSession::asyncWrite()
{
    std::ostringstream output_sstream, header_stream; 
    std::vector<boost::asio::const_buffer> buffers;

    // load the serialized data
    output_sstream << m_stream_value;
    m_outbound_data = output_sstream.str();

    // get the size of the output stream
    header_stream << std::setw(sizeof(m_inbound_header)) << std::hex << m_outbound_data.size();
    m_outbound_header = header_stream.str();

    buffers.push_back(boost::asio::buffer(m_outbound_header));
    if(m_outbound_data.size() != 0)
        buffers.push_back(boost::asio::buffer(m_outbound_data));
        
    auto self(this->shared_from_this());
    boost::asio::async_write(m_socket, buffers,
                            [this, self](const boost::system::error_code& error_code, size_t length)
    {
        if(!error_code)
        {
            BOOST_LOG_TRIVIAL(debug) << "Successfully wrote " << length << " bytes to the client";
            asyncRead();
        }
        else 
            BOOST_LOG_TRIVIAL(error) << "AsyncWrite Error (error_code): " << error_code.message();
    });
}

TcpServerManager::TcpServerManager(const std::string& certif_file, 
                     const std::string& priv_key_file, 
                     const std::string& dh_file,
                     const unsigned short port, 
                     std::shared_ptr<StreamableBase> stream_value)
        : m_io_context(), 
          m_acceptor(m_io_context, tcp::endpoint(tcp::v4(), port)),
          m_ssl_context(boost::asio::ssl::context::sslv23),
          m_stream_value(stream_value)
{
    m_ssl_context.set_options(boost::asio::ssl::context::default_workarounds
                            | boost::asio::ssl::context::no_sslv2
                            | boost::asio::ssl::context::single_dh_use);

    m_ssl_context.set_password_callback(std::bind(&TcpServerManager::getPassword, this));
    m_ssl_context.use_certificate_chain_file(certif_file);
    m_ssl_context.use_private_key_file(priv_key_file, boost::asio::ssl::context::pem);
    m_ssl_context.use_tmp_dh_file(dh_file);

    acceptConnections();
    m_io_context.run();
}

TcpServerManager::~TcpServerManager()
{}

std::string TcpServerManager::getPassword() const
{
    return "test";
}

void TcpServerManager::acceptConnections()
{
    m_acceptor.async_accept([this](const boost::system::error_code& error_code, tcp::socket socket)
    {
        if(!error_code)
        {
            BOOST_LOG_TRIVIAL(info) << "Accepted a connection";
            std::shared_ptr<TcpSession> session = std::make_shared<TcpSession>(boost::asio::ssl::stream<tcp::socket>(std::move(socket), m_ssl_context), m_stream_value);
            session->start();
        }
        acceptConnections();
    });
}

void TcpServerManager::run()
{
    m_io_context.run();
}