#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>
#include <chrono>
#include <algorithm>

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#   define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#include <httplib.h>

namespace {

class Server {
    public:
        explicit
        Server(int port = 0)
            : _M_port(port)
            , _M_bound_port(0)
            , _M_received_stop_signal(false)
            , _M_server(std::make_shared<httplib::Server>())
            , _M_listen_thread()
        {
        }

        virtual ~Server() {
            try {
                stop();
            } catch (std::exception const &e) {
                std::clog << "[c++ exception] " << e.what() << std::endl;
            } catch (...) {
            }
        }

        void start() {
            if (_M_bound_port != 0)
                return;
            std::clog << "server start..." << std::endl;
            _M_received_stop_signal = false;
            if (!_M_server)
                _M_server = std::make_shared<httplib::Server>();
            std::string host = "0.0.0.0";
            if (_M_port == 0) {
                _M_bound_port = _M_server->bind_to_any_port(host.c_str());
                if (_M_bound_port <= 0 || _M_bound_port > 65536)
                    throw std::runtime_error("bind_to_any_port");
            } else {
                if (!_M_server->bind_to_port(host.c_str(), _M_port))
                    throw std::runtime_error("bind_to_port");
                _M_bound_port = _M_port;
            }
            std::clog
                << "bound to " << host
                << ":" << _M_bound_port
                << std::endl;
            std::exception_ptr ep;
            _M_listen_thread = std::thread([this, &ep]() {
                        try {
                            if (!this->_M_server->listen_after_bind())
                                throw std::runtime_error("listen_after_bind");
                        } catch (...) {
                            if (!this->_M_received_stop_signal)
                                ep = std::current_exception();
                        }
                    });
            while (!_M_server->is_valid() || !_M_server->is_running()) {
                if (!!ep)
                    std::rethrow_exception(ep);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            std::clog << "server started." << std::endl;
        }

        void stop() {
            if (!_M_server)
                return;
            if (_M_bound_port == 0)
                return;
            std::clog << "server stop..." << std::endl;
            _M_received_stop_signal = true;
            if (_M_server->is_running())
                _M_server->stop();
            if (_M_listen_thread.joinable()) {
                _M_listen_thread.join();
                std::clog
                    << "unbound from 0.0.0.0:" << _M_bound_port
                    << std::endl;
            }
            _M_bound_port = 0;
            _M_server = NULL;
            std::clog << "server stopped." << std::endl;
        }

        std::shared_ptr<httplib::Server> getInternalServer() {
            return _M_server;
        }

        int getBoundPort() const {
            return _M_bound_port;
        }

        int getPort() const {
            return _M_port;
        }

        void setPort(int value) {
            _M_port = value;
        }
    protected:
    private:
        int _M_port;
        int _M_bound_port;
        bool _M_received_stop_signal;
        std::shared_ptr<httplib::Server> _M_server;
        std::thread _M_listen_thread;

        Server(Server const&);
        Server& operator=(Server const&);
};

template <typename U, typename V>
struct sstream_cast_impl {
    static V do_cast(U const &u) {
        V v;
        std::stringstream ss;
        ss << u;
        ss >> v;
        return v;
    }
};

template <typename U>
struct sstream_cast_impl<U, std::string> {
    static std::string do_cast(U const &u) {
        std::ostringstream oss;
        oss << u;
        return oss.str();
    }
};

template <typename V, typename U>
V sstream_cast(U const &u) {
    return sstream_cast_impl<U, V>::do_cast(u);
}

template <typename V>
V sstream_cast(char const *s) {
    return sstream_cast_impl<char const*, V>::do_cast(s);
}

bool check_partial_support(
        httplib::Client &client,
        std::string const &path,
        int64_t &content_length) {
    httplib::Result const &r = client.Head(path.c_str());
    if (r.error() != httplib::Error::Success)
        throw std::runtime_error(httplib::to_string(r.error()));
    if (!r)
        throw std::runtime_error("No Response");
    if (r->status != 200) {
        std::ostringstream es;
        es << "HTTP Status: " << r->status << std::endl;
        throw std::runtime_error(es.str());
    }
    if (!r->has_header("Accept-Ranges"))
        return false;
    if (r->get_header_value("Accept-Ranges") == "none")
        return false;
    if (!r->has_header("Content-Length"))
        return false;
    content_length = sstream_cast<int64_t>(
            r->get_header_value("Content-Length"));
    return true;
}

void download_partial(
        httplib::Client &client,
        std::string const &path,
        long off,
        long pos) {
    httplib::Headers headers;
    httplib::Ranges ranges;
    ranges.push_back({off, pos});
    headers.insert(httplib::make_range_header(ranges));
    // FIXME check modification
    // https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Range_requests
    httplib::Result const &r = client.Get(path.c_str(), headers);
    if (r.error() != httplib::Error::Success)
        throw std::runtime_error(httplib::to_string(r.error()));
    // should be 206 Partial Content
    if (r->status != 206) {
        std::ostringstream es;
        es << "HTTP Status: " << r->status;
        throw std::runtime_error(es.str());
    }
    std::cout << "path = " << path << std::endl;
    std::cout << "part = " << ranges[0].first << " - " << ranges[0].second << std::endl;
    std::cout << "body(" << r->body.size() << ") = " << r->body << std::endl;
}

class Ranger {
    public:
        Ranger(int64_t total_size, int64_t max_partial_size)
            : _M_max_partial_size(max_partial_size)
            , _M_total_size(total_size)
            , _M_remain_size(_M_total_size)
            , _M_offset(0)
            , _M_length(0)
        {
        }

        bool next() {
            if (_M_remain_size <= 0)
                return false;
            if (_M_remain_size >= _M_max_partial_size) {
                _M_offset = _M_total_size - _M_remain_size;
                _M_length = _M_max_partial_size;
            } else {
                _M_offset = _M_total_size - _M_remain_size;
                _M_length = _M_remain_size;
            }
            _M_remain_size -= _M_length;
            return true;
        }

        int64_t offset() const {
            return _M_offset;
        }

        int64_t length() const {
            return _M_length;
        }
    protected:
    private:
        int64_t _M_max_partial_size;
        int64_t _M_total_size;
        int64_t _M_remain_size;
        int64_t _M_offset;
        int64_t _M_length;
};

} // namespace

int main(int argc, char* argv[]) try {
    // setup server
    Server server;
    std::string home = getenv("HOME");
    if (!server.getInternalServer()->set_mount_point("/downloads", home + "/Downloads"))
        throw std::runtime_error("set_mount_point");
    server.start();
    std::ostringstream builder;
    builder << "http://127.0.0.1:" << server.getBoundPort();
    httplib::Client client(builder.str());

    std::string path = "/downloads/WePE64_V2.2.iso.txt";
    long content_length = 0;
    long max_partial_size = 64;
    if (check_partial_support(client, path, content_length)) {
        // download partially
        Ranger ranger(content_length, max_partial_size);
        while (ranger.next())
            download_partial(
                    client,
                    path,
                    ranger.offset(),
                    ranger.offset() + ranger.length() - 1);
    }
    return EXIT_SUCCESS;
} catch (std::exception const &e) {
    std::cerr << "[c++ exception] " << e.what() << std::endl;
    return EXIT_FAILURE;
} catch (...) {
    std::cerr << "[c++ exception] " << "<UNKNOWN>" << std::endl;
    return EXIT_FAILURE;
}
