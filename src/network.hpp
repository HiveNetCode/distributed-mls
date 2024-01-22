/**
 * @file network.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Handle low level network operations for clients
 */

#ifndef __NETWORK_HPP__
#define __NETWORK_HPP__

#include <algorithm>
#include <bits/chrono.h>
#include <bits/types/struct_timeval.h>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <sys/time.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>

#include "check.hpp"
#include "message.hpp"
#include "pki.hpp"
#include "pki_client.hpp"

using timePoint = std::chrono::time_point<std::chrono::system_clock>;
using timeoutID = size_t;
using timeoutCallback = std::function<void(const timeoutID &)>;

static constexpr int BUF_SIZE = 4096;

struct Buffer
{
    uint8_t * data;
    size_t curSize, reservedSize;

    Buffer(): data(NULL), curSize(0), reservedSize(0) {}

    Buffer(const Buffer & buf): data(buf.data), curSize(buf.curSize),
        reservedSize(buf.reservedSize) {}

    Buffer & operator=(const Buffer & buf)
    {
        data = buf.data;
        curSize = buf.curSize;
        reservedSize = buf.reservedSize;

        return *this;
    }

    void init(size_t size)
    {
        data = (uint8_t *) malloc(size);
        if(!data)
            sys_error("Allocating buffer failed");

        curSize = 0;
        reservedSize = size;
    }

    void free()
    {
        if(data)
            std::free(data);
    }

    void realloc(size_t newSizeMin)
    {
        const size_t newSize = std::max(reservedSize * 2, newSizeMin);
        data = (uint8_t *) std::realloc(data, newSize);
        if(!data)
            sys_error("Expanding buffer failed");

        reservedSize = newSize;

        // TODO Should also decrease size when buffer is too big sometimes
    }

    void append(const uint8_t * src, size_t size)
    {
        if(curSize + size > reservedSize)
            realloc(curSize + size);

        memcpy(data + curSize, src, size);
        curSize += size;
    }

    void pop(uint8_t * dst, size_t size)
    {
        assert(size <= curSize);

        memcpy(dst, data, size);
        memmove(data, data + size, curSize - size);
        curSize -= size;

        // TODO Ideally check to reduce buffer size
    }

    Bytes packAndFree()
    {
        Bytes buf{curSize};
        memcpy(buf.content, data, curSize);

        free();
        return buf;
    }
};

class Network
{

public:
    Network(const char * pkiAddress, int server)
        : m_pkiAddress(pkiAddress), m_server(server)
    { }

    void runSelect(const std::function<bool(void)> & notifyIn)
    {
        bool goon = true;

        fd_set readSet;
        int maxFds;

        while(goon)
        {
            maxFds = m_server;

            timeval * timeout = nullptr;
            auto closestTimeout = nextTimeout();
            
            while(closestTimeout && closestTimeout->first.tv_sec == 0
                && closestTimeout->first.tv_usec == 0)
            {
                auto timeoutID = closestTimeout->second;

                m_timeouts[timeoutID].second(timeoutID);
                unregisterTimeout(timeoutID);

                closestTimeout = nextTimeout();
            }
            if(closestTimeout)
                timeout = &closestTimeout->first;

            FD_ZERO(&readSet);
            FD_SET(0, &readSet);
            FD_SET(m_server, &readSet);

            for(const auto& client : m_inboundClients)
            {
                FD_SET(client, &readSet);
                if(client > maxFds)
                    maxFds = client;
            }

            int selectRes = select(maxFds+1, &readSet, NULL, NULL, timeout);
            PCHECK(selectRes);

            if(selectRes == 0 && closestTimeout)
            {
                auto timeoutID = closestTimeout->second;

                m_timeouts[timeoutID].second(timeoutID);
                unregisterTimeout(timeoutID);
            }

            if(FD_ISSET(0, &readSet))
            {
                goon = notifyIn();
            }

            if(FD_ISSET(m_server, &readSet))
            {
                struct sockaddr_in clientAddr;
                socklen_t clientLen = sizeof(struct sockaddr_in);

                int newClient = accept(m_server, (struct sockaddr *) &clientAddr, &clientLen);
                PCHECK(newClient);

                Buffer buf;
                buf.init(BUF_SIZE);

                m_inboundClients.insert(newClient);
                m_incomingSize[newClient] = 0;
                m_incomingMessage[newClient] = buf;
            }

            for(auto it = m_inboundClients.begin(); it != m_inboundClients.end(); )
            {
                if(FD_ISSET(*it, &readSet) && !readClient(*it))
                    it = m_inboundClients.erase(it); // Remove if connection terminated
                else
                    ++it;
            }
        }
    }

    timeoutID registerTimeout(int msDelay, timeoutCallback callback)
    {
        timeoutID timeoutID = m_timeoutCounter++;

        timePoint targetedTime = std::chrono::system_clock::now()
            + std::chrono::milliseconds{msDelay};
        m_timeouts.insert({timeoutID, { targetedTime, callback }});

        return timeoutID;
    }

    void unregisterTimeout(timeoutID id)
    {
        m_timeouts.erase(id);
    }

    void setHandleMessage(const std::function<void(Bytes &)> & handleMessage)
    {
        if(!m_handleMessage)
            m_handleMessage = handleMessage;
    }

    void connect(const std::string & id)
    {
        if(m_outboundClients.count(id))
            return;

        PKIQueryResponse resp = queryAddrPKI(m_pkiAddress, id);

        int s = socket(AF_INET, SOCK_STREAM, 0);
        PCHECK(s);

        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(resp.port),
            .sin_addr = { .s_addr = htonl(resp.ip.s_addr) }
        };
        PCHECK(::connect(s, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)));

        m_outboundClients[id] = s;
    }

    void disconnect(const std::string & id)
    {
        if(!m_outboundClients.count(id))
            return;

        close(m_outboundClients[id]);
        m_outboundClients.erase(id);
    }

    void broadcast(const Bytes & message)
    {
        for(const auto & client : m_outboundClients)
            netWrite(client.second, message);
    }

    void broadcastSample(const std::vector<std::string> & sample, const Bytes & message)
    {
        for(const auto & id : sample)
            if(m_outboundClients.count(id))
            {
                const auto & client = m_outboundClients[id];
                netWrite(client, message);
            }
    }

    void send(const std::string & id, const Bytes & message)
    {
        connect(id); // No effect if already connected

        const auto & client = m_outboundClients[id];
        netWrite(client, message);
    }

protected:
    bool readClient(int client)
    {
        uint8_t buf[BUF_SIZE];

        ssize_t n = read(client, buf, BUF_SIZE);
        if(n <= 0)
        {
            close(client);
            m_incomingMessage[client].free();
            return false;
        }

        assert(n > 0);

        size_t expected = m_incomingSize[client];
        Buffer clientBuf = m_incomingMessage[client];

        clientBuf.append(buf, n);

        while(clientBuf.curSize >= expected)
        {
            if(expected == 0)
            {
                if(clientBuf.curSize < 4)
                    break;

                uint32_t msgSize;
                clientBuf.pop((uint8_t *) &msgSize, 4);

                expected = ntoh(msgSize);
            }
            else
            {
                Bytes message(expected);
                clientBuf.pop(message.content, expected);

                if(m_handleMessage)
                    m_handleMessage(message);

                expected = 0;
            }
        }

        m_incomingSize[client] = expected;
        m_incomingMessage[client] = clientBuf;

        return true;
    }

    static timeval remainingTimeval(const timePoint & timePoint)
    {
        auto now = std::chrono::system_clock::now();
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            timePoint - now);

        if(remaining.count() <= 0)
        {
            return (timeval) { .tv_sec = 0, .tv_usec = 0 };
        }
        
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(remaining);
        auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            remaining - seconds);

        return (timeval) { .tv_sec = seconds.count(), .tv_usec = microseconds.count() };
    }

    std::optional<std::pair<timeval, timeoutID>> nextTimeout()
    {
        if(m_timeouts.empty())
            return {};
        else
        {
            const auto chosen = std::min_element(
                m_timeouts.begin(), m_timeouts.end(),
                [](const auto & lhs, const auto & rhs)
                { return lhs.second.first < rhs.second.first; });

            return {{ remainingTimeval(chosen->second.first), chosen->first }};
        }
    }

private:
    const char * m_pkiAddress;
    const int m_server;
    std::unordered_set<int> m_inboundClients;
    std::unordered_map<std::string, int> m_outboundClients;

    std::function<void(Bytes &)> m_handleMessage;
    std::unordered_map<int, size_t> m_incomingSize;
    std::unordered_map<int, Buffer> m_incomingMessage;

    timeoutID m_timeoutCounter = 0;
    std::unordered_map<timeoutID, std::pair<timePoint, timeoutCallback>> m_timeouts;
};

#endif
