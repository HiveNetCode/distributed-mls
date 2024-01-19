/**
 * @file pki.cpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Simplified PKI for MLS and DGKA
 */

#include "pki.hpp"

#include <map>
#include <queue>
#include <string>

#include <netinet/in.h>
#include <sys/socket.h>

#include "check.hpp"
#include "message.hpp"

std::map<std::string, std::queue<Bytes>> prekeys;
std::map<std::string, struct sockaddr_in> addresses;

#ifdef PRINT
#   define print(a) a
#else
#   define print(a) 
#endif

#ifdef PRINT
void print_bin_string(const char * str)
{
    while (*str != '\0')
    {
        if (isprint(*str))
            putchar(*str);
        else
            printf("x%02X", (unsigned char) *str);
        str++;
    }
}
void print_bytes(const char * bytes, uint size)
{
    printf("[");
    for(uint idx = 0; idx < size; ++idx)
        printf("%02X", (unsigned char) bytes[idx]);
    printf("]");
}
#endif

void process(int c, const struct sockaddr_in& addr)
{
    PKIRequest req = PKIRecvRequest(c);

    if(req.type == REQUEST_PUBLISH)
    {
        print(printf("Publish request "); print_bin_string(req.pubRequest.id.c_str()); printf(" "); print_bytes((char *) req.pubRequest.keys[0].content, req.pubRequest.keys[0].size); printf("...\n");)

        addresses[req.pubRequest.id] = {
            .sin_port = ntoh(addr.sin_port),
            .sin_addr = { .s_addr = ntoh(addr.sin_addr.s_addr) }
        };
        addresses[req.pubRequest.id].sin_port = req.pubRequest.port;

        std::queue<Bytes> keys;
        for(const auto& bs : req.pubRequest.keys)
            keys.emplace(bs);
        prekeys[req.pubRequest.id] = keys;

        PKIPublishResponse resp;
        resp.success = 1;
        PKISendPublishResponse(c, resp);
    }
    else if(req.type == REQUEST_QUERY || req.type == REQUEST_ADDR)
    {
        print(printf("Query request "); print_bin_string(req.queryRequestId.c_str()); printf("\n");)

        PKIQueryResponse resp;
        if(prekeys.count(req.queryRequestId) > 0
            && addresses.count(req.queryRequestId) > 0
            && (req.type == REQUEST_ADDR || prekeys[req.queryRequestId].size() > 0))
        {
            resp.success = 1;

            if(req.type == REQUEST_QUERY)
            {
                resp.preKey = prekeys[req.queryRequestId].front();
                prekeys[req.queryRequestId].pop();
            }
            
            resp.ip = addresses[req.queryRequestId].sin_addr;
            resp.port = addresses[req.queryRequestId].sin_port;
        }
        else
            resp.success = 0;

        PKISendQueryResponse(c, resp);
    }
}

int main()
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if(s == -1)
        sys_error("Error Opening socket");

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PKI_PORT),
        .sin_addr =
            { .s_addr = INADDR_ANY }
    };

    if(bind(s, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) == -1)
        sys_error("Error binding socket to port");

    if(listen(s, 100) == -1)
        sys_error("Error listening to socket");

    while(1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(struct sockaddr_in);
        int c = accept(s, (struct sockaddr *) &client_addr, &client_addr_len);

        if(c == -1)
            sys_error("Error accepting client");

        process(c, client_addr);
        close(c);
    }

    return 0;
}
