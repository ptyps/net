#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <vector>
#include <string>
#include <list>

#include "pstd.hpp"

namespace net {
  struct exception : public std::exception {
    private:
      std::string message;

    public:
      template <typename ...A>
        exception(pstd::vstring str, A ...args) {
          message = pstd::format(str, args ...);
        }

      pstd::cstring what() const noexcept override {
        return message.data();
      }
  };

  enum class event {
    ERROR = EOF,
    DISCONNECTED
  };

  enum class status {
    FAIL = EOF,
    OK
  };

  enum class family {
    Unknown = EOF,
    Unspecified,
    IPv6,
    IPv4
  };

  enum class proto {
    Unknown = EOF,
    IP,
    TCP,
    UDP
  };

  enum class type {
    Unknown = EOF,
    STREAM,
    RAW
  };

  // ----

  // determines whether or not an IP address is valid IPv6
  bool isIPv6(pstd::vstring ip) {
    auto sa = sockaddr_in6();
    auto i = ::inet_pton(AF_INET6, &ip[0], &(sa.sin6_addr));

    return (i == 1) ? !0 : !1;
  }

  // determines whether or not an IP address is valid IPv4
  bool isIPv4(pstd::vstring ip) {
    auto sa = sockaddr_in();
    auto i = ::inet_pton(AF_INET, &ip[0], &(sa.sin_addr));

    return (i == 1) ? !0 : !1;
  }

  // ----

  void set_family(addrinfo* &ai, family f) {
    switch (f) {
      case family::IPv6:
        ai->ai_family = AF_INET6;
        break;

      case family::IPv4:
        ai->ai_family = AF_INET;
        break;

      case family::Unknown:
        ai->ai_family = AF_UNSPEC;
        break;

      default:
        throw exception("unable to set family");
    }
  }

  family get_family(addrinfo* ai) {
    if (ai->ai_family == AF_INET6)
      return family::IPv6;

    else if (ai->ai_family == AF_INET)
      return family::IPv4;

    else 
      return family::Unknown;
  }

  family get_family(pstd::vstring addr) {
    if (isIPv6(addr))
      return family::IPv6;

    if (isIPv4(addr))
      return family::IPv4;

    return family::Unknown;
  }

  // ----
  
  void set_proto(addrinfo* &ai, proto p) {   
    switch (p) {
      case proto::IP:
        ai->ai_protocol = IPPROTO_IP;
        break;

      case proto::TCP:
        ai->ai_protocol = IPPROTO_TCP;
        break;

      case proto::UDP:
        ai->ai_protocol = IPPROTO_UDP;
        break;

      default:
        throw exception("unable to set protocol");
    }
  }
  
  proto get_proto(addrinfo* ai) {
    if (ai->ai_protocol == IPPROTO_IP)
      return proto::IP;

    if (ai->ai_protocol == IPPROTO_TCP)
      return proto::TCP;

    if (ai->ai_protocol == IPPROTO_UDP)
      return proto::UDP;

    return proto::Unknown;
  }

  // ----
  
  void set_type(addrinfo* &ai, type t) {   
    switch (t) {
      case type::STREAM:
        ai->ai_socktype = SOCK_STREAM;
        break;

      case type::RAW:
        ai->ai_socktype = SOCK_RAW;
        break;

      default:
        throw exception("unable to set type");
    }
  }

  type get_type(addrinfo* ai) {
    if (ai->ai_socktype == SOCK_STREAM)
      return type::STREAM;

    if (ai->ai_socktype == SOCK_RAW)
      return type::RAW;

    return type::Unknown;
  }

  // ----

  void set_addr(addrinfo* &ai, pstd::vstring addr) {
    set_family(ai, get_family(addr));

    switch (ai->ai_family) {
      case AF_INET6: {
        ai->ai_addr = (sockaddr *) new sockaddr_in6();
        ai->ai_addrlen = sizeof(sockaddr_in6);
        
        inet_pton(AF_INET6, &addr[0], &((sockaddr_in6 *) ai->ai_addr)->sin6_addr);
        break;
      }

      case AF_INET: {
        ai->ai_addr = (sockaddr *) new sockaddr_in();
        ai->ai_addrlen = sizeof(sockaddr_in);

        inet_pton(AF_INET, &addr[0], &((sockaddr_in *) ai->ai_addr)->sin_addr);
        break;
      }

      default:
        throw exception("unable to set addr");
    }
  }

  std::string get_addr(addrinfo* ai) {
    auto out = std::string();

    switch (ai->ai_family) {
      case AF_INET6: {
        auto ia = ((sockaddr_in6 *) ai->ai_addr)->sin6_addr;
        inet_ntop(AF_INET6, &ia, &out[0], INET6_ADDRSTRLEN);
        break;
      }

      case AF_INET: {
        auto ia = ((sockaddr_in *) ai->ai_addr)->sin_addr;
        out = (std::string) inet_ntoa(ia);
        break;
      }

      default:
        throw exception("addrinfo* has invalid family");
    }

    return out.data();
  }

  // ----

  uint16_t get_port(addrinfo* ai) {
    auto out = int(0);

    switch (ai->ai_family) {
      case AF_INET6:
        out = ((sockaddr_in6 *) ai->ai_addr)->sin6_port;
        break;

      case AF_INET:
        out = ((sockaddr_in *) ai->ai_addr)->sin_port;
        break;

      default:
        throw exception("addrinfo* has invalid family");
    }

    return ntohs(out);
  }

  // assign port
  void set_port(addrinfo* &ai, uint16_t p) {
    switch (ai->ai_family) {
      case AF_INET6:
        ((sockaddr_in6 *) ai->ai_addr)->sin6_port = htons(p);
        break;

      case AF_INET:
        ((sockaddr_in *) ai->ai_addr)->sin_port = htons(p);
        break;

      default:
        throw exception("unable to set port, no recognized family");
    }
  }

  // ----

  // return a list of IPv4 and/or IPv6 addresses
  std::list<std::string> lookup(pstd::vstring host, family f = family::Unspecified) {
    auto out = std::list<std::string>();

    auto ai = new addrinfo();

    getaddrinfo(&host[0], NULL, NULL, &ai);

    for (auto next = ai; next != NULL; next = next->ai_next) {
      auto currently = get_family(next);

      if (f == family::Unspecified || currently == f) {
        auto it = get_addr(next);

        auto found = pstd::find(out, [&](auto ip) { return ip == it; });

        if (!found)
          out.push_back(it);
      }
    }

    return out;
  }

  std::list<std::string> lookupIPv6(pstd::vstring host) {
    return lookup(host, family::IPv6);
  }

  std::list<std::string> lookupIPv4(pstd::vstring host) {
    return lookup(host, family::IPv4);
  }

  // ----

  status option(uint id, uint opt, uint on = !0) {
    auto i = ::setsockopt(id, SOL_SOCKET, opt, &on, sizeof(int));

    return (i != EOF) ?
      status::OK : status::FAIL;
  }

  std::optional<uint> open(addrinfo* ai) {
    auto i = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

    if (i == EOF)
      return {};

    return i;
  }

  status connect(uint id, addrinfo* ai) {
    auto i = ::connect(id, ai->ai_addr, ai->ai_addrlen);

    return (i != EOF) ?
      status::OK : status::FAIL;
  }

  status bind(uint id, addrinfo* ai) {
    auto i = ::bind(id, ai->ai_addr, ai->ai_addrlen);

    return (i != EOF) ?
      status::OK : status::FAIL;
  }

  status close(uint id) {
    return ::close(id) != EOF ?
      status::FAIL : status::OK;
  }

  status listen(uint id, uint length = 1) {
    auto i = ::listen(id, length);

    return (i != EOF) ?
      status::OK : status::FAIL;
  }

  std::pair<uint, addrinfo*> accept(uint id, addrinfo* ai) {
    while (!0) {
      auto ca = new addrinfo({
        .ai_family = ai->ai_family,
        .ai_addrlen = ai->ai_addrlen
      });

      switch (ai->ai_family) {
        case AF_INET6:
          ca->ai_addr = (sockaddr *) new sockaddr_in6();
          break;

        case AF_INET:
          ca->ai_addr = (sockaddr *) new sockaddr_in();
          break;

        default:
          throw pstd::exception("invalid family");
      }

      auto i = ::accept(id, ca->ai_addr, &ca->ai_addrlen);

      if (i == EOF)
        continue;

      return std::pair(i, ca);
    }
  }

  std::variant<event, std::string> recv(uint id, uint size = 1024) {
    auto buffer = std::vector<char>(size);
    auto recvd = std::string("");
    auto len = int(0);

    while (!0) {
      auto i = ::recv(id, &buffer[0], size, 0);

      if (i == EOF) {
        if (errno == EAGAIN)
          continue;

        return event::ERROR;
      }

      if (i == 0)
        return event::DISCONNECTED;

      auto begin = std::begin(buffer);
      auto end = std::end(buffer);
      
      recvd += std::string(begin, end);
      buffer.clear();
      len += i;

      if (i < size)
        return recvd.substr(0, len);
    }
  }

  std::variant<event, std::string> recv(SSL* sid, uint size = 1024) {
    auto buffer = std::vector<char>(size);
    auto recvd = std::string("");
    auto len = int(0);

    while (!0) {
      auto i = SSL_read(sid, &buffer[0], size);

      if (i == EOF) {
        if (errno == EAGAIN)
          continue;

        return event::ERROR;
      }

      if (i == 0)
        return event::DISCONNECTED;

      auto begin = std::begin(buffer);
      auto end = std::end(buffer);
      
      recvd += std::string(begin, end);
      buffer.clear();
      len += i;

      if (i < size)
        return recvd.substr(0, len);
    }
  }

  template <typename ...A>
    void send(uint id, pstd::vstring text, A ...args) {
      auto out = pstd::format(text, args ...);
      auto offset = 0;

      while (offset < out.length())
        offset += ::send(id, out.substr(offset).data(), out.substr(offset).length(), 0);
    }

  template <typename ...A>
    void send(SSL* sid, pstd::vstring text, A ...args) {
      auto out = pstd::format(text, args ...);
      auto offset = 0;

      while (offset < out.length())
        offset += ::SSL_write(sid, out.substr(offset).data(), out.substr(offset).length(), 0);
    }
}
