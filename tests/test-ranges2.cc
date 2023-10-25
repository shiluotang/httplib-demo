#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>
#include <chrono>
#include <algorithm>

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#   define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#ifdef __clang__
#	pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <httplib.h>
#ifdef __clang__
#	pragma clang diagnostic warning "-Wdeprecated-declarations"
#endif

namespace fs {

int64_t get_file_size(std::string const &filename) {
    std::ifstream infile(
            filename.c_str(),
            std::ios_base::in | std::ios_base::binary);
    if (!infile)
        throw std::runtime_error("failed to open " + filename + " for read!");
    auto pos0 = infile.tellg();
    infile.seekg(0, std::ios_base::end);
    auto pos = infile.tellg();
    std::streamoff size = pos - pos0;
    infile.close();
    return size;
}

void rename(std::string const &oname, std::string const &nname) {
    if (std::rename(oname.c_str(), nname.c_str()) != 0)
        throw std::runtime_error("failed to rename " + oname + " => " + nname);
}

void append(std::string const &filename, char const *data, size_t size) {
    std::ofstream outfile(filename.c_str(), std::ios_base::out | std::ios_base::app);
    if (!outfile)
        throw std::runtime_error("failed to open " + filename + " for write");
    std::cout
        << "fs::append(" << filename
        << ", " << static_cast<void const*>(data)
        << ", " << size
        << ")"
        << std::endl;
    outfile.write(data, size);
}

void write(std::string const &filename, char const *data, size_t size) {
    std::ofstream outfile(filename.c_str(), std::ios_base::out | std::ios_base::trunc);
    if (!outfile)
        throw std::runtime_error("failed to open " + filename + " for write");
    outfile.write(data, size);
}

} // namespace fs

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

class Downloader {
    public:
        explicit Downloader(
                std::string const &partial_suffix = ".part",
                int max_trials = 10)
            : max_trials_(max_trials)
            , partial_suffix_(partial_suffix)
        {
        }

        std::string getPartialSuffix() const {
            return partial_suffix_;
        }

        void setPartialSuffix(std::string const &value) {
            partial_suffix_ = value;
        }

        int getMaxTrials() const {
            return max_trials_;
        }

        void setMaxTrials(int value) {
            max_trials_ = value;
        }

        bool doDownload(
                std::string const &resource_url,
                std::string const &filename) {
            std::string temporary_filename = filename + partial_suffix_;
            std::string scheme_and_host;
            std::string resource_path;
            if (!breakup_url(resource_url, scheme_and_host, resource_path)) {
                std::cout << "breakup_url failed" << std::endl;
                return false;
            }
            std::cout << "scheme_and_host = " << scheme_and_host << std::endl;
            std::cout << "resource_path = " << resource_path << std::endl;
            httplib::Client client(scheme_and_host.c_str());
            client.set_logger([this](
                        httplib::Request const &req,
                        httplib::Response const &res) {
                        dump_http_request(req);
                        dump_http_response(res);
                    });
            auto res = client.Head(resource_path.c_str());
            bool support_ranges_request = false;
            bool maybe_support_ranges_request = false;
            int64_t content_length = 0;
            bool resource_not_found = false;
            // probe ranges request capability
            if (!res) {
                std::cout << "No response" << std::endl;
                return false;
            }
            if (res->status == 200) {
                if (res->has_header("Accept-Ranges")) {
                    if (res->get_header_value("Accept-Ranges") == "bytes") {
                        support_ranges_request = true;
                        if (res->has_header("Content-Length"))
                            content_length = sstream_cast<int64_t>(
                                    res->get_header_value("Content-Length"));
                    } else {
                        // typically Accept-Ranges: none
                        support_ranges_request = false;
                        if (res->has_header("Content-Length"))
                            content_length = sstream_cast<int64_t>(
                                    res->get_header_value("Content-Length"));
                    }
                } else {
                    // maybe do not support ranges request
                }
            } else {
                if (res->status == 404) {
                    std::cout << "resource not found!" << std::endl;
                    resource_not_found = true;
                } else {
                    // ignore status other than "404 Not Found"
                    maybe_support_ranges_request = true;
                }
            }
            if (resource_not_found)
                return false;
            bool completed = false;
            std::cout << "before trails" << std::endl;
            for (int trials = 0; trials < max_trials_ && !completed; ++trials) {
                std::cout << "trials #" << trials << std::endl;
                int64_t already_downloaded_size = 0;
                try {
                    already_downloaded_size = fs::get_file_size(temporary_filename);
                } catch (std::runtime_error const&) {
                    // ignore non such file exception
                }
                if (content_length > 0 && already_downloaded_size == content_length) {
                    // finished
                    fs::rename(temporary_filename, filename);
                    return true;
                }
                httplib::Headers headers;
                if (support_ranges_request || maybe_support_ranges_request) {
                    httplib::Ranges ranges;
                    ranges.push_back(std::make_pair<>(already_downloaded_size, -1));
                    headers.insert(httplib::make_range_header(ranges));
                }
                httplib::Request req;
                httplib::Response res;
                httplib::Error err;
                httplib::ContentReceiver receiver =
                    [temporary_filename, &res](char const *data, size_t size)  {
                        try {
                            if (res.status == 206) {
                                // 206 Partial Content
                                fs::append(temporary_filename, data, size);
                            } else if (res.status == 200) {
                                // 202 OK
                                fs::write(temporary_filename, data, size);
                            }
                            return true;
                        } catch (std::runtime_error const &e) {
                            std::cout << "[c++ exception] " << e.what() << std::endl;
                            return false;
                        } catch (...) {
                            std::cout << "[c++ exception] " << "<UNKNOWN>" << std::endl;
                            return false;
                        }
                    };
                req.method = "GET";
                req.path = resource_path;
                req.content_receiver = [&receiver](
                        char const* data,
                        size_t size,
                        uint64_t offset,
                        uint64_t length) {
                    return receiver(data, size);
                };
                req.headers = headers;
                if (!client.send(req, res, err)) {
                    std::cout << "err = " << httplib::to_string(err) << std::endl;
                    if (res.status == 206
                            || res.status == 200
                            || res.status == -1) {
                        // res.status == -1 => no response received
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                        continue;
                    } else {
                        // FIXME?
                        std::cout << "res.status == " << res.status << std::endl;
                        return false;
                    }
                }
                fs::rename(temporary_filename, filename);
                // TODO How to determine
                completed = true;
            }
            return false;
        }
    protected:
        static
        void dump_http_request(httplib::Request const &r) {
            std::ostream &os = std::cout;
            os << "REQ.METHOD = " << r.method << std::endl;
            for (auto it = r.headers.begin(); it != r.headers.end(); ++it)
                os << "REQ.HEADER[" << it->first << "] = " << it->second << std::endl;
        }

        static
        void dump_http_response(httplib::Response const &r) {
            std::ostream &os = std::cout;
            os << "RES.STATUS = " << r.status << std::endl;
            for (auto it = r.headers.begin(); it != r.headers.end(); ++it)
                os << "RES.HEADER[" << it->first << "] = " << it->second << std::endl;
            if (r.status != 200 && r.status != 206)
                os << "RES.BODY = " << r.body << std::endl;
        }

        static
        bool breakup_url(
                std::string const &url,
                std::string &scheme_and_host,
                std::string &path) {
            std::string::size_type off = 0;
            std::string scheme_notation = "://";
            std::string::size_type pos = url.find(scheme_notation, off);
            if (pos == std::string::npos)
                return false;
            off = pos + scheme_notation.length();
            pos = url.find("/", off);
            if (pos == std::string::npos)
                pos = url.length();
            scheme_and_host = url.substr(0, pos);
            path = url.substr(pos);
            if (path.empty())
                path = "/";
            return true;
        }
    private:
        int max_trials_;
        std::string partial_suffix_;
};

std::string find_filename(std::string const &url) {
    std::string::size_type pos1 = url.find_first_of("?#", 0);
    if (pos1 == std::string::npos)
        pos1 = url.length();
    std::string::size_type pos0 = url.rfind("/", pos1);
    if (pos0 == std::string::npos)
        pos0 = url.length();
    else
        pos0 = pos0 + 1;
    return url.substr(pos0, pos1 - pos0);
}

} // namespace

int main(int argc, char* argv[]) try {
    std::string path = "https://mirrors.tuna.tsinghua.edu.cn/ubuntu-releases/14.04/ubuntu-14.04.6-server-amd64.template";
    std::string filename = "";
    if (argc > 1)
        path = argv[1];
    if (argc > 2)
        filename = argv[2];
    if (filename.empty())
        filename = find_filename(path);
    if (filename.empty())
        filename = "unnamed";
    // download(path, filename);
    Downloader downloader;
    downloader.doDownload(path, filename);
    return EXIT_SUCCESS;
} catch (std::exception const &e) {
    std::cerr << "[c++ exception] " << e.what() << std::endl;
    return EXIT_FAILURE;
} catch (...) {
    std::cerr << "[c++ exception] " << "<UNKNOWN>" << std::endl;
    return EXIT_FAILURE;
}
