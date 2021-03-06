/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2019,  Arizona Board of Regents.
 *
 * This file is part of ndn-tools (Named Data Networking Essential Tools).
 * See AUTHORS.md for complete list of ndn-tools authors and contributors.
 *
 * ndn-tools is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndn-tools is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-tools, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author: Jerald Paul Abraham <jeraldabraham@email.arizona.edu>
 * @author: Eric Newberry <enewberry@email.arizona.edu>
 */

#include "core/common.hpp"
#include "core/version.hpp"

#include "drop.hpp"
#include "statistics-collector.hpp"
#include "tracer.hpp"

namespace ndn {
    namespace drop {
        namespace client {

            class Runner : noncopyable {
            public:
                explicit
                Runner(const Options &options)
                        : m_drop(m_face, options, m_keyChain), m_statisticsCollector(m_drop, options),
                          m_tracer(m_drop, options), m_signalSetInt(m_face.getIoService(), SIGINT),
                          m_signalSetQuit(m_face.getIoService(), SIGQUIT) {
                    m_signalSetInt.async_wait(bind(&Runner::afterIntSignal, this, _1));
                    m_signalSetQuit.async_wait(bind(&Runner::afterQuitSignal, this, _1));

                    m_drop.afterFinish.connect([this] {
                        this->cancel();
                    });
                }

                int
                run(std::string module) {
                    try {
                        if (module == "discover") {
                            m_drop.start();
                            m_face.processEvents();
                        }
                    }
                    catch (const std::exception &e) {
                        m_tracer.onError(e.what());
                        return 2;
                    }

                    Statistics statistics = m_statisticsCollector.computeStatistics();

                    std::cout << statistics << std::endl;

                    if (statistics.nReceived == statistics.nSent) {
                        return 0;
                    } else {
                        return 1;
                    }
                }

            private:
                void
                cancel() {
                    m_signalSetInt.cancel();
                    m_signalSetQuit.cancel();
                    m_drop.stop();
                }

                void
                afterIntSignal(const boost::system::error_code &errorCode) {
                    if (errorCode == boost::asio::error::operation_aborted) {
                        return;
                    }

                    cancel();
                }

                void
                afterQuitSignal(const boost::system::error_code &errorCode) {
                    if (errorCode == boost::asio::error::operation_aborted) {
                        return;
                    }

                    // m_statisticsCollector.computeStatistics().printSummary(std::cout);
                    m_signalSetQuit.async_wait(bind(&Runner::afterQuitSignal, this, _1));
                }

            private:
                Face m_face;
                KeyChain m_keyChain;
                Drop m_drop;
                StatisticsCollector m_statisticsCollector;
                Tracer m_tracer;

                boost::asio::signal_set m_signalSetInt;
                boost::asio::signal_set m_signalSetQuit;
            };

            static time::milliseconds
            getMinimumDropInterval() {
                return time::milliseconds(1);
            }

            static time::milliseconds
            getDefaultDropInterval() {
                return time::milliseconds(1000);
            }

            static time::milliseconds
            getDefaultDropTimeoutThreshold() {
                return time::milliseconds(4000);
            }

            static void
            usage(const boost::program_options::options_description &options) {
                std::cout << "Usage: ndndrop [options] ndn:/name/prefix\n"
                             "\n"
                             "Drop a NDN name prefix using Interests with name ndn:/name/prefix/drop/number.\n"
                             "The numbers in the Interests are randomly generated unless specified.\n"
                             "\n"
                          << options;
                exit(2);
            }

            static int
            main(int argc, char *argv[]) {
                Options options;
                options.shouldAllowStaleData = false;
                options.nDrops = -1;
                options.interval = time::milliseconds(getDefaultDropInterval());
                options.timeout = time::milliseconds(getDefaultDropTimeoutThreshold());
                options.startSeq = 0;
                options.shouldGenerateRandomSeq = true;
                options.shouldPrintTimestamp = false;

                std::string identifier;

                namespace po = boost::program_options;

                po::options_description visibleOptDesc("Options");
                visibleOptDesc.add_options()
                        ("help,h", "print this message and exit")
                        ("version,V", "display version and exit")
                        ("interval,i",
                         po::value<time::milliseconds::rep>()->default_value(getDefaultDropInterval().count()),
                         "drop interval, in milliseconds")
                        ("timeout,o",
                         po::value<time::milliseconds::rep>()->default_value(getDefaultDropTimeoutThreshold().count()),
                         "drop timeout, in milliseconds")
                        ("count,c", po::value<int>(&options.nDrops), "number of drops to send (default = no limit)")
                        ("start,n", po::value<uint64_t>(&options.startSeq),
                         "set the starting sequence number, the number is incremented by 1 after each Interest")
                        ("identifier,p", po::value<std::string>(&identifier),
                         "add identifier to the Interest names before the sequence numbers to avoid conflicts")
                        ("cache,a", "allow routers to return stale Data from cache")
                        ("timestamp,t", "print timestamp with messages");

                po::options_description hiddenOptDesc;
                hiddenOptDesc.add_options()
                        ("prefix", po::value<std::string>(), "prefix to send drops to");
                hiddenOptDesc.add_options()
                        ("home_name", po::value<std::string>(), "home network name");
                hiddenOptDesc.add_options()
                        ("node_name", po::value<std::string>(), "device name");
                hiddenOptDesc.add_options()
                        ("module", po::value<std::string>(), "module to run");
                po::options_description optDesc;
                optDesc.add(visibleOptDesc).add(hiddenOptDesc);

                po::positional_options_description optPos;

                optPos.add("prefix", 1);
                optPos.add("home_name", 1);
                optPos.add("node_name", 1);
                optPos.add("module", 1);
                std::string module;
                try {
                    po::variables_map optVm;
                    po::store(po::command_line_parser(argc, argv).options(optDesc).positional(optPos).run(), optVm);
                    po::notify(optVm);

                    if (optVm.count("help") > 0) {
                        usage(visibleOptDesc);
                    }

                    if (optVm.count("version") > 0) {
                        std::cout << "ndndrop " << tools::VERSION << std::endl;
                        exit(0);
                    }

                    if (optVm.count("prefix") > 0 ) {
                        options.prefix = Name(optVm["prefix"].as<std::string>());
                    } else {
                        std::cerr << "ERROR: No prefix specified" << std::endl;
                        usage(visibleOptDesc);
                    }

                    if (optVm.count("home_name") > 0 && optVm.count("node_name") > 0 && optVm.count("module") > 0) {
                        options.home_name = optVm["home_name"].as<std::string>();
                        options.node_name = optVm["node_name"].as<std::string>();
                        module = optVm["module"].as<std::string>();
                        std::cout << "Home: " << options.home_name << " Node: " << options.node_name << std::endl;
                    } else {
                        std::cerr << "ERROR: No home_name and node_name specified" << std::endl;
                        usage(visibleOptDesc);
                    }

                    options.interval = time::milliseconds(optVm["interval"].as<time::milliseconds::rep>());
                    if (options.interval < getMinimumDropInterval()) {
                        std::cerr << "ERROR: Specified drop interval is less than the minimum " <<
                                  getMinimumDropInterval() << std::endl;
                        usage(visibleOptDesc);
                    }

                    options.timeout = time::milliseconds(optVm["timeout"].as<time::milliseconds::rep>());

                    if (optVm.count("count") > 0) {
                        if (options.nDrops <= 0) {
                            std::cerr << "ERROR: Number of drop must be positive" << std::endl;
                            usage(visibleOptDesc);
                        }
                    }

                    if (optVm.count("start") > 0) {
                        options.shouldGenerateRandomSeq = false;
                    }

                    if (optVm.count("identifier") > 0) {
                        bool isIdentifierAcceptable = std::all_of(identifier.begin(), identifier.end(), &isalnum);
                        if (identifier.empty() || !isIdentifierAcceptable) {
                            std::cerr << "ERROR: Unacceptable client identifier" << std::endl;
                            usage(visibleOptDesc);
                        }

                        options.clientIdentifier = name::Component(identifier);
                    }

                    if (optVm.count("cache") > 0) {
                        options.shouldAllowStaleData = true;
                    }

                    if (optVm.count("timestamp") > 0) {
                        options.shouldPrintTimestamp = true;
                    }
                }
                catch (const po::error &e) {
                    std::cerr << "ERROR: " << e.what() << std::endl;
                    usage(visibleOptDesc);
                }

                return Runner(options).run(module);
            }

        } // namespace client
    } // namespace drop
} // namespace ndn

int
main(int argc, char *argv[]) {
    return ndn::drop::client::main(argc, argv);
}
