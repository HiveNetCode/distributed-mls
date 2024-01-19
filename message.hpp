/**
 * @file message.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Utility to read and write message from/to network
 */

#ifndef __MESSAGE_HPP__
#define __MESSAGE_HPP__

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

/** Generic/network order functions */

// https://stackoverflow.com/a/13352059
template <typename T>
static inline T _swap_any(const T &input)
{
    T output(0);
    const std::size_t size = sizeof(T);
    uint8_t *data = reinterpret_cast<uint8_t *>(&output);

    for (std::size_t i = 0; i < size; i++) {
        data[i] = input >> ((size - i - 1) * 8);
    }

    return output;
}

template <typename T>
static inline T hton(const T &input)
{
# if __BYTE_ORDER == __LITTLE_ENDIAN
    return _swap_any(input);
# elif __BYTE_ORDER == __BIG_ENDIAN
    return input;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
}

#define ntoh(input) hton(input)

/** Common types */

struct Bytes
{
    Bytes(size_t size_ = 0): size(size_)
    {
        content = new uint8_t[size];
    }

    Bytes(const Bytes & bs)
        : size(bs.size)
    {
        content = new uint8_t[size];
        memcpy(content, bs.content, size);
    }

    Bytes& operator=(const Bytes& other)
    {
        size = other.size;
        content = new uint8_t[size];
        memcpy(content, other.content, size);

        return *this;
    }

    ~Bytes()
    {
        delete[] content;
    }

    uint32_t size;
    uint8_t * content;
};

/** Network read */

static bool netRead(int s, uint8_t & value)
{
    ssize_t n;
    while((n = recv(s, &value, 1, 0)) == 0)
        ;

    return n == 1;
}

static bool netRead(int s, uint8_t * bytes, size_t size)
{
    ssize_t n;
    while((n = recv(s, (void *) bytes, size, 0)) >= 0 && n < size)
        bytes += n, size -= n;

    return n != -1;
}

template <typename T>
static bool netRead(int s, T & value)
{
    union { T intVal; uint8_t data[sizeof(T)]; };

    if(!netRead(s, data, sizeof(T)))
        return false;

    value = ntoh(intVal);
    return true;
}

static bool netRead(int s, std::string& str)
{
    str = "";
    uint8_t c;
    while(netRead(s, c) && c != '\0')
        str += c;

    return c == '\0';
}

// TODO Add soft limit to bytes size (prevent attacks)
static bool netRead(int s, Bytes& bs)
{
    uint32_t size;
    if(!netRead(s, size))
        return false;

    bs = Bytes(size);
    if(!netRead(s, bs.content, size))
        return false;

    return true;
}


/** Network write */

static bool netWrite(int s, uint8_t value)
{
    ssize_t n;
    while((n = send(s, &value, 1, 0)) == 0)
        ;

    return n == 1;
}

static bool netWrite(int s, const uint8_t * bytes, size_t size)
{
    ssize_t n;

    const int flags = MSG_NOSIGNAL; // Avoid SIGPIPE on terminated socket
    while((n = send(s, bytes, size, flags)) >= 0 && n < size)
        bytes += n, size -= n;

    return n != -1;
}

template <typename T>
static bool netWrite(int s, T value)
{
    union { T intVal; uint8_t data[sizeof(T)]; };
    intVal = hton(value);

    return netWrite(s, data, sizeof(T));
}

static bool netWrite(int s, const std::string& str)
{
    return netWrite(s, (const uint8_t *) str.c_str(), str.size()+1);
}

static bool netWrite(int s, const Bytes & bs)
{
    if(!netWrite(s, bs.size))
        return false;

    return netWrite(s, bs.content, bs.size);
}

#endif
