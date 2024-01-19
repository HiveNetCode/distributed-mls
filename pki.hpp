/**
 * @file pki.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Specification of the Simplified PKI for MLS and Weidner et al. DGKA
 * 
 * Main functions:
 * - Store prekeys for users and reachability infos
 * - Retrieve prekey of a user and reachability infos
 *
 * Users are identify by a string
 */

/* Protocol specification
Server listens to Request message and answer with Response messages

Request:
{
    type: u32,
    select(type)
    {
        case PUBLISH: PublishRequest
        case QUERY:   QueryRequest
        case ADDR:    QueryRequest
    }
}

string: {chars: u8[], '\0'}
bytes: {size: u32, content: u8[size]}

PublishRequest:
{
    identity: string,
    port: u16,
    keyCount: u32,
    keys: bytes[keyCount]
}

QueryRequest:
{
    identity: string
}

Response:
{
    u8: success,
    if(success)
    {
        select(Request.type)
        {
            case QUERY: { ip: u32, port: u16, prekey: bytes }
            case ADDR:  { ip: u32, port: u16 }
        }
    }
}
*/

#ifndef __PKI_HPP__
#define __PKI_HPP__

#include <cstdint>
#include <netinet/in.h>
#include <string>
#include <vector>

#include "check.hpp"
#include "message.hpp"

enum PKIRequestType: uint32_t
{
    REQUEST_PUBLISH = 1,
    REQUEST_QUERY,
    REQUEST_ADDR
};

struct PKIPublishRequest
{
    std::string id;
    uint16_t port;
    std::vector<Bytes> keys;
};

struct PKIRequest
{
    PKIRequestType type;

    // union
    // {
        PKIPublishRequest pubRequest;
        std::string queryRequestId;
    // };
};

struct PKIQueryResponse
{
    uint8_t success;
    
    struct in_addr ip;
    uint16_t port;
    Bytes preKey;
};

struct PKIPublishResponse
{
    uint8_t success;
};

static constexpr uint16_t PKI_PORT = 10501;

/** Network io */

static PKIRequest PKIRecvRequest(int s)
{
    uint32_t type;
    CHECK(netRead(s, type));

    PKIRequest req;
    switch(type)
    {
        case REQUEST_PUBLISH:
            req.type = REQUEST_PUBLISH;

            CHECK(netRead(s, req.pubRequest.id));
            CHECK(netRead(s, req.pubRequest.port));

            uint32_t count;
            CHECK(netRead(s, count));
            for(uint32_t idx = 0; idx < count; ++idx)
            {
                Bytes bs;
                CHECK(netRead(s, bs));
                req.pubRequest.keys.emplace_back(bs);
            }
            break;

        case REQUEST_QUERY:
            req.type = REQUEST_QUERY;
            CHECK(netRead(s, req.queryRequestId));
            break;

        case REQUEST_ADDR:
            req.type = REQUEST_ADDR;
            CHECK(netRead(s, req.queryRequestId));
            break;

        default:
            ERROR("Invalid PKI Request Type");
    }

    return req;
}

static void PKISendRequest(int s, const PKIRequest & req)
{
    if(req.type == REQUEST_PUBLISH)
    {
        CHECK(netWrite(s, (uint32_t) req.type));
        CHECK(netWrite(s, req.pubRequest.id));
        CHECK(netWrite(s, req.pubRequest.port));
        CHECK(netWrite(s, (uint32_t) req.pubRequest.keys.size()));
        for(const auto& bs : req.pubRequest.keys)
            CHECK(netWrite(s, bs));
    }
    else if(req.type == REQUEST_QUERY || req.type == REQUEST_ADDR)
    {
        CHECK(netWrite(s, (uint32_t) req.type));
        CHECK(netWrite(s, req.queryRequestId));
    }
}

static PKIQueryResponse PKIRecvQueryResponse(int s)
{
    PKIQueryResponse resp;

    CHECK(netRead(s, resp.success));

    if(resp.success)
    {
        uint32_t addr;
        CHECK(netRead(s, addr));
        resp.ip.s_addr = addr;
        
        CHECK(netRead(s, resp.port));
        CHECK(netRead(s, resp.preKey));
    }
    return resp;
}

static PKIQueryResponse PKIRecvAddrResponse(int s)
{
    PKIQueryResponse resp;

    CHECK(netRead(s, resp.success));

    if(resp.success)
    {
        uint32_t addr;
        CHECK(netRead(s, addr));
        resp.ip.s_addr = addr;
        
        CHECK(netRead(s, resp.port));
    }
    return resp;
}

static PKIPublishResponse PKIRecvPublishResponse(int s)
{
    PKIPublishResponse resp;
    CHECK(netRead(s, resp.success));
    return resp;
}

static void PKISendQueryResponse(int s, const PKIQueryResponse & resp)
{
    if(!netWrite(s, resp.success))
    {
        fprintf(stderr, "Error send query response on %d\n", s);
        return;
    }

    if(resp.success)
    {
        bool success = netWrite(s, (uint32_t) resp.ip.s_addr)
            && netWrite(s, resp.port)
            && netWrite(s, resp.preKey);

        if(!success)
            fprintf(stderr, "Error send query response on %d\n", s);
    }
}

static void PKISendAddrResponse(int s, const PKIQueryResponse & resp)
{
    if(!netWrite(s, resp.success))
    {
        fprintf(stderr, "Error send addr response on %d\n", s);
        return;
    }

    if(resp.success)
    {
        bool success = netWrite(s, (uint32_t) resp.ip.s_addr)
            && netWrite(s, resp.port);

        if(!success)
            fprintf(stderr, "Error send addr response on %d\n", s);
    }
}

static void PKISendPublishResponse(int s, const PKIPublishResponse & resp)
{
    if(!netWrite(s, resp.success))
    {
        fprintf(stderr, "Error send publish response on %d\n", s);
        return;
    }
}

#endif
