#pragma once

#include <string>
#include <vector>
#include <iostream>
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
    #define SHUT_RDWR SD_BOTH
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
    typedef int SOCKET;
#endif

/**
 * @class SocketClient
 * @brief Socket client for sending data to remote servers
 */
class SocketClient
{
private:
    SOCKET mSocket;
    std::string mHost;
    uint16_t mPort;
    bool mConnected;

    void initializeSocketLibrary()
    {
#ifdef _WIN32
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            throw std::runtime_error("WSAStartup failed: " + std::to_string(result));
        }
#endif
    }

    void cleanupSocketLibrary()
    {
#ifdef _WIN32
        WSACleanup();
#endif
    }

public:
    /**
     * @brief Constructor
     * @param host The hostname or IP address to connect to
     * @param port The port number
     */
    SocketClient(const std::string& host, uint16_t port)
        : mSocket(INVALID_SOCKET), mHost(host), mPort(port), mConnected(false)
    {
        initializeSocketLibrary();
    }

    /**
     * @brief Destructor - closes connection if active
     */
    ~SocketClient()
    {
        disconnect();
        cleanupSocketLibrary();
    }

    /**
     * @brief Connect to the remote server
     * @return true if successful, false otherwise
     */
    bool connect()
    {
        if (mConnected) {
            return true;
        }

        try {
            // Create socket
            mSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (mSocket == INVALID_SOCKET) {
                throw std::runtime_error("Failed to create socket");
            }

            // Resolve hostname
            struct hostent* host = gethostbyname(mHost.c_str());
            if (host == nullptr) {
                closesocket(mSocket);
                mSocket = INVALID_SOCKET;
                throw std::runtime_error("Failed to resolve hostname: " + mHost);
            }

            // Prepare address structure
            struct sockaddr_in serverAddr;
            std::memset(&serverAddr, 0, sizeof(serverAddr));
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(mPort);
            std::memcpy(&serverAddr.sin_addr, host->h_addr, host->h_length);

            // Connect to server
            if (::connect(mSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
                closesocket(mSocket);
                mSocket = INVALID_SOCKET;
                throw std::runtime_error("Failed to connect to " + mHost + ":" + std::to_string(mPort));
            }

            mConnected = true;
            std::cout << "Connected to " << mHost << ":" << mPort << std::endl;
            return true;

        } catch (const std::exception& e) {
            std::cerr << "Connection error: " << e.what() << std::endl;
            return false;
        }
    }

    /**
     * @brief Disconnect from the server
     */
    void disconnect()
    {
        if (mConnected && mSocket != INVALID_SOCKET) {
            shutdown(mSocket, SHUT_RDWR);
            closesocket(mSocket);
            mSocket = INVALID_SOCKET;
            mConnected = false;
            std::cout << "Disconnected from " << mHost << ":" << mPort << std::endl;
        }
    }

    /**
     * @brief Send data to the server
     * @param data The data to send
     * @return Number of bytes sent, -1 on error
     */
    int send(const std::vector<unsigned char>& data)
    {
        if (!mConnected) {
            std::cerr << "Not connected" << std::endl;
            return -1;
        }

        int bytesSent = ::send(mSocket, (const char*)data.data(), data.size(), 0);
        if (bytesSent == SOCKET_ERROR) {
            std::cerr << "Send failed" << std::endl;
            return -1;
        }

        return bytesSent;
    }

    /**
     * @brief Send data to the server (string version)
     * @param data The string data to send
     * @return Number of bytes sent, -1 on error
     */
    int send(const std::string& data)
    {
        std::vector<unsigned char> bytes(data.begin(), data.end());
        return send(bytes);
    }

    /**
     * @brief Receive data from the server
     * @param bufferSize Maximum bytes to receive
     * @return Received data
     */
    std::vector<unsigned char> receive(size_t bufferSize = 4096)
    {
        if (!mConnected) {
            std::cerr << "Not connected" << std::endl;
            return {};
        }

        std::vector<unsigned char> buffer(bufferSize);
        int bytesReceived = ::recv(mSocket, (char*)buffer.data(), bufferSize, 0);

        if (bytesReceived == SOCKET_ERROR) {
            std::cerr << "Receive failed" << std::endl;
            return {};
        }

        if (bytesReceived == 0) {
            std::cout << "Connection closed by server" << std::endl;
            mConnected = false;
            return {};
        }

        buffer.resize(bytesReceived);
        return buffer;
    }

    /**
     * @brief Send data with length prefix
     * @param data The data to send
     * @return true if successful
     */
    bool sendWithLength(const std::vector<unsigned char>& data)
    {
        if (!mConnected) {
            std::cerr << "Not connected" << std::endl;
            return false;
        }

        // Send 4-byte length prefix (big-endian)
        uint32_t length = data.size();
        unsigned char lengthBytes[4];
        lengthBytes[0] = (length >> 24) & 0xFF;
        lengthBytes[1] = (length >> 16) & 0xFF;
        lengthBytes[2] = (length >> 8) & 0xFF;
        lengthBytes[3] = length & 0xFF;

        if (::send(mSocket, (const char*)lengthBytes, 4, 0) != 4) {
            std::cerr << "Failed to send length prefix" << std::endl;
            return false;
        }

        // Send data
        if (::send(mSocket, (const char*)data.data(), data.size(), 0) != (int)data.size()) {
            std::cerr << "Failed to send data" << std::endl;
            return false;
        }

        return true;
    }

    /**
     * @brief Receive data with length prefix
     * @return Received data
     */
    std::vector<unsigned char> receiveWithLength()
    {
        if (!mConnected) {
            std::cerr << "Not connected" << std::endl;
            return {};
        }

        // Receive 4-byte length prefix
        unsigned char lengthBytes[4];
        if (::recv(mSocket, (char*)lengthBytes, 4, 0) != 4) {
            std::cerr << "Failed to receive length prefix" << std::endl;
            return {};
        }

        uint32_t length = ((uint32_t)lengthBytes[0] << 24) |
                         ((uint32_t)lengthBytes[1] << 16) |
                         ((uint32_t)lengthBytes[2] << 8) |
                         ((uint32_t)lengthBytes[3]);

        if (length > 100 * 1024 * 1024) {  // Sanity check: max 100MB
            std::cerr << "Received length too large: " << length << std::endl;
            return {};
        }

        // Receive data
        std::vector<unsigned char> buffer(length);
        size_t totalReceived = 0;
        while (totalReceived < length) {
            int bytesReceived = ::recv(mSocket, (char*)(buffer.data() + totalReceived),
                                      length - totalReceived, 0);
            if (bytesReceived <= 0) {
                std::cerr << "Failed to receive data" << std::endl;
                return {};
            }
            totalReceived += bytesReceived;
        }

        return buffer;
    }

    /**
     * @brief Check if currently connected
     * @return true if connected
     */
    bool isConnected() const
    {
        return mConnected;
    }

    /**
     * @brief Get the host
     * @return The hostname/IP
     */
    const std::string& getHost() const
    {
        return mHost;
    }

    /**
     * @brief Get the port
     * @return The port number
     */
    uint16_t getPort() const
    {
        return mPort;
    }
};

/**
 * @class SocketServer
 * @brief Simple socket server for receiving data
 */
class SocketServer
{
private:
    SOCKET mServerSocket;
    SOCKET mClientSocket;
    uint16_t mPort;
    bool mRunning;

    void initializeSocketLibrary()
    {
#ifdef _WIN32
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            throw std::runtime_error("WSAStartup failed: " + std::to_string(result));
        }
#endif
    }

    void cleanupSocketLibrary()
    {
#ifdef _WIN32
        WSACleanup();
#endif
    }

public:
    /**
     * @brief Constructor
     * @param port The port to listen on
     */
    SocketServer(uint16_t port)
        : mServerSocket(INVALID_SOCKET), mClientSocket(INVALID_SOCKET), 
          mPort(port), mRunning(false)
    {
        initializeSocketLibrary();
    }

    /**
     * @brief Destructor
     */
    ~SocketServer()
    {
        stop();
        cleanupSocketLibrary();
    }

    /**
     * @brief Start the server
     * @return true if successful
     */
    bool start()
    {
        try {
            // Create socket
            mServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (mServerSocket == INVALID_SOCKET) {
                throw std::runtime_error("Failed to create socket");
            }

            // Set socket options
            int reuse = 1;
            if (setsockopt(mServerSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) == SOCKET_ERROR) {
                throw std::runtime_error("setsockopt failed");
            }

            // Bind socket
            struct sockaddr_in serverAddr;
            std::memset(&serverAddr, 0, sizeof(serverAddr));
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
            serverAddr.sin_port = htons(mPort);

            if (bind(mServerSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
                throw std::runtime_error("Bind failed");
            }

            // Listen
            if (listen(mServerSocket, SOMAXCONN) == SOCKET_ERROR) {
                throw std::runtime_error("Listen failed");
            }

            mRunning = true;
            std::cout << "Server listening on port " << mPort << std::endl;
            return true;

        } catch (const std::exception& e) {
            std::cerr << "Server start error: " << e.what() << std::endl;
            return false;
        }
    }

    /**
     * @brief Accept a client connection
     * @return true if successful
     */
    bool acceptConnection()
    {
        if (!mRunning) {
            std::cerr << "Server not running" << std::endl;
            return false;
        }

        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);

        mClientSocket = accept(mServerSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (mClientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed" << std::endl;
            return false;
        }

        std::cout << "Client connected from " << inet_ntoa(clientAddr.sin_addr) << std::endl;
        return true;
    }

    /**
     * @brief Receive data from connected client
     * @param bufferSize Maximum bytes to receive
     * @return Received data
     */
    std::vector<unsigned char> receive(size_t bufferSize = 4096)
    {
        if (mClientSocket == INVALID_SOCKET) {
            std::cerr << "No client connected" << std::endl;
            return {};
        }

        std::vector<unsigned char> buffer(bufferSize);
        int bytesReceived = ::recv(mClientSocket, (char*)buffer.data(), bufferSize, 0);

        if (bytesReceived == SOCKET_ERROR || bytesReceived == 0) {
            std::cerr << "Receive failed or connection closed" << std::endl;
            return {};
        }

        buffer.resize(bytesReceived);
        return buffer;
    }

    /**
     * @brief Send data to connected client
     * @param data The data to send
     * @return Number of bytes sent, -1 on error
     */
    int send(const std::vector<unsigned char>& data)
    {
        if (mClientSocket == INVALID_SOCKET) {
            std::cerr << "No client connected" << std::endl;
            return -1;
        }

        int bytesSent = ::send(mClientSocket, (const char*)data.data(), data.size(), 0);
        if (bytesSent == SOCKET_ERROR) {
            std::cerr << "Send failed" << std::endl;
            return -1;
        }

        return bytesSent;
    }

    /**
     * @brief Stop the server
     */
    void stop()
    {
        if (mClientSocket != INVALID_SOCKET) {
            shutdown(mClientSocket, SHUT_RDWR);
            closesocket(mClientSocket);
            mClientSocket = INVALID_SOCKET;
        }

        if (mServerSocket != INVALID_SOCKET) {
            closesocket(mServerSocket);
            mServerSocket = INVALID_SOCKET;
        }

        mRunning = false;
    }

    /**
     * @brief Check if server is running
     * @return true if running
     */
    bool isRunning() const
    {
        return mRunning;
    }

    /**
     * @brief Check if client is connected
     * @return true if client connected
     */
    bool hasClient() const
    {
        return mClientSocket != INVALID_SOCKET;
    }

    /**
     * @brief Send data with length prefix
     * @param data The data to send
     * @return true if successful
     */
    bool sendWithLength(const std::vector<unsigned char>& data)
    {
        if (mClientSocket == INVALID_SOCKET) {
            std::cerr << "No client connected" << std::endl;
            return false;
        }

        // Send 4-byte length prefix (big-endian)
        uint32_t length = data.size();
        unsigned char lengthBytes[4];
        lengthBytes[0] = (length >> 24) & 0xFF;
        lengthBytes[1] = (length >> 16) & 0xFF;
        lengthBytes[2] = (length >> 8) & 0xFF;
        lengthBytes[3] = length & 0xFF;

        if (::send(mClientSocket, (const char*)lengthBytes, 4, 0) != 4) {
            std::cerr << "Failed to send length prefix" << std::endl;
            return false;
        }

        // Send data
        if (::send(mClientSocket, (const char*)data.data(), data.size(), 0) != (int)data.size()) {
            std::cerr << "Failed to send data" << std::endl;
            return false;
        }

        return true;
    }

    /**
     * @brief Receive data with length prefix
     * @return Received data
     */
    std::vector<unsigned char> receiveWithLength()
    {
        if (mClientSocket == INVALID_SOCKET) {
            std::cerr << "No client connected" << std::endl;
            return {};
        }

        // Receive 4-byte length prefix
        unsigned char lengthBytes[4];
        if (::recv(mClientSocket, (char*)lengthBytes, 4, 0) != 4) {
            std::cerr << "Failed to receive length prefix" << std::endl;
            return {};
        }

        uint32_t length = ((uint32_t)lengthBytes[0] << 24) |
                         ((uint32_t)lengthBytes[1] << 16) |
                         ((uint32_t)lengthBytes[2] << 8) |
                         ((uint32_t)lengthBytes[3]);

        if (length > 100 * 1024 * 1024) {  // Sanity check: max 100MB
            std::cerr << "Received length too large: " << length << std::endl;
            return {};
        }

        // Receive data
        std::vector<unsigned char> buffer(length);
        size_t totalReceived = 0;
        while (totalReceived < length) {
            int bytesReceived = ::recv(mClientSocket, (char*)(buffer.data() + totalReceived),
                                      length - totalReceived, 0);
            if (bytesReceived <= 0) {
                std::cerr << "Failed to receive data" << std::endl;
                return {};
            }
            totalReceived += bytesReceived;
        }

        return buffer;
    }
};
