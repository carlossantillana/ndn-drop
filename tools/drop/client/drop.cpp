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
 * @author: Teng Liang <philoliang@email.arizona.edu>
 */

#include "drop.hpp"
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <pthread.h>
#include <unistd.h>

using namespace std;

bool debug = true;

namespace ndn {
    namespace drop {
        namespace client {

            Drop::Drop(Face &face, const Options &options, KeyChain& keyChain)
                    : m_options(options), m_nSent(0), m_nextSeq(options.startSeq), m_nOutstanding(0), m_face(face),
                      m_scheduler(m_face.getIoService()),
                      m_keyChain(keyChain),
                      m_nDrops(0) {
                if (m_options.shouldGenerateRandomSeq) {
                    m_nextSeq = random::generateWord64();
                }
                //events.push_back([this] { performDrop(); });
                events.push_back([this] { performDiscover(); });
                event_index = 0;
                auto b = make_shared<Buffer>();
                b->assign(m_options.payloadSize, 'a');
                m_payload = Block(tlv::Content, std::move(b));
                m_thread = std::thread(&Drop::monitor_neighbor_list, this);
            }

            void
            Drop::monitor_neighbor_list() {
                while (true && m_running) {
                    neighborListLock.lock();
                    neighborList.decrementList();
                    neighborListLock.unlock();
                    sleep(m_options.lifetime);
                }
            }

            std::vector<std::string>
            Drop::split (const std::string &s, char delim) {
                std::vector<std::string> result;
                std::stringstream ss (s);
                std::string item;

                while (getline (ss, item, delim)) {
                    result.push_back (item);
                }

                return result;
            }

            void
            Drop::start() {
                m_registeredPrefix = m_face.setInterestFilter(
                        Name("ndn/broadcast/drop/discover").append(m_options.home_name),
                        bind(&Drop::onInterest, this, _2),
                        [] (const auto&, const auto& reason) {
                            NDN_THROW(std::runtime_error("Failed to register prefix: " + reason));
                        });
                runDrop();
                //performDiscover();
                //performDrop();
            }

            void
            Drop::onInterest(const Interest& interest)
            {
                afterReceive(interest.getName());
                //std::cout << "Received an interest: " << interest.getName() << std::endl;
                std::vector<std::string> tokens = split(interest.getName().toUri(), '/');
                if (tokens.size() <= 6) {
                    cout << "Error: invalid discover name: " << interest.getName().toUri();
                }
                std::string home_name = tokens.at(5);
                std::string node_name = tokens.at(6);
                if (home_name.compare(m_options.home_name) == 0 && node_name.compare(m_options.node_name) == 0) {
                    //std::cout << "Ignoring message from self!" << std::endl;
                    return;
                }

                // random backoff
                int microseconds = rand() % 750000;
                usleep(microseconds);

                std::string neighborName = "/" + home_name + "/" + node_name;
                neighborListLock.lock();
                neighborList.addNeighbor(neighborName);
                std::string reachableList = neighborList.serializeList();
                neighborListLock.unlock();

                std::vector<uint8_t> buffer(reachableList.begin(), reachableList.end());

                auto data = make_shared<Data>(interest.getName());
                data->setFreshnessPeriod(m_options.freshnessPeriod);
                //cout << "Sending: " << reachableList << endl;
                //cout << reachableList.length() << endl;
                data->setContent(buffer.data(), static_cast<size_t>(reachableList.length()));

                m_keyChain.sign(*data, signingWithSha256());
                m_face.put(*data);
                ++m_nDrops;
                if (m_options.nMaxDrops > 0 && m_options.nMaxDrops == m_nDrops) {
                    afterFinish();
                }
            }

            void
            Drop::stop() {
                m_nextDropEvent.cancel();
                m_registeredPrefix.cancel();
                m_running = false;
                m_thread.join();
            }

            void
            Drop::performDiscover() {
                BOOST_ASSERT((m_options.nDrops < 0) || (m_nSent < m_options.nDrops));

                Name name = makeDiscoverName(m_nextSeq);
                //cout << "Sending discover message with name: " << name.toUri() << endl;
                //cout << endl;
                Interest interest(name);
                interest.setCanBePrefix(false);
                interest.setMustBeFresh(!m_options.shouldAllowStaleData);
                interest.setInterestLifetime(m_options.timeout);

                auto now = time::steady_clock::now();
                m_face.expressInterest(interest,
                                       //bind(&Drop::onData, this, m_nextSeq, now),
                                       bind(&Drop::handleData, this,  _1, _2),
                                       bind(&Drop::onNack, this, _2, m_nextSeq, now),
                                       bind(&Drop::onTimeout, this, m_nextSeq));

                ++m_nSent;
                ++m_nextSeq;
                ++m_nOutstanding;

                if ((m_options.nDrops < 0) || (m_nSent < m_options.nDrops)) {
                    //m_nextDropEvent = m_scheduler2.scheduleEvent(1000000000, m_options.interval, [this] { performDiscover(); });
                    m_nextDropEvent = m_scheduler.schedule(m_options.interval, [this] { runDrop(); });
                } else {
                    finish();
                }
            }



            void
            Drop::performDrop() {
                BOOST_ASSERT((m_options.nDrops < 0) || (m_nSent < m_options.nDrops));

                //std::cout << makeDropName(m_nextSeq) << std::endl;
                Interest interest(makeDropName(m_nextSeq));
                interest.setCanBePrefix(false);
                interest.setMustBeFresh(!m_options.shouldAllowStaleData);
                interest.setInterestLifetime(m_options.timeout);

                auto now = time::steady_clock::now();
                m_face.expressInterest(interest,
                                       bind(&Drop::onData, this, m_nextSeq, now),
                                       bind(&Drop::onNack, this, _2, m_nextSeq, now),
                                       bind(&Drop::onTimeout, this, m_nextSeq));

                ++m_nSent;
                ++m_nextSeq;
                ++m_nOutstanding;
                if ((m_options.nDrops < 0) || (m_nSent < m_options.nDrops)) {
                    //m_nextDropEvent = m_scheduler1.scheduleEvent(1000000000, m_options.interval, [this] { performDrop(); });
                    m_nextDropEvent = m_scheduler.schedule(m_options.interval, [this] { runDrop(); });
                } else {
                    finish();
                }
            }

            void
            Drop::runDrop() {
                if ((m_options.nDrops < 0) || (m_nSent < m_options.nDrops)) {
                    m_nextDropEvent = m_scheduler.schedule(m_options.interval, events.at((event_index++) % events.size()));
                } else {
                    finish();
                }
            }

            void
            Drop::sayHello() {
                printf("sayHello(): hello\n");
            }

            void
            Drop::onData(uint64_t seq, const time::steady_clock::TimePoint &sendTime) {
                time::nanoseconds rtt = time::steady_clock::now() - sendTime;
                afterData(seq, rtt);
                finish();
            }

            void
            Drop::onNack(const lp::Nack &nack, uint64_t seq, const time::steady_clock::TimePoint &sendTime) {
                time::nanoseconds rtt = time::steady_clock::now() - sendTime;
                afterNack(seq, rtt, nack.getHeader());
                finish();
            }

            void
            Drop::onTimeout(uint64_t seq) {
                afterTimeout(seq);
                finish();
            }

            void
            Drop::finish() {
                if (--m_nOutstanding >= 0) {
                    return;
                }
                afterFinish();
            }

            Name
            Drop::makeDropName(uint64_t seq) const {
                Name name(m_options.prefix);
                name.append("drop");
                if (!m_options.clientIdentifier.empty()) {
                    name.append(m_options.clientIdentifier);
                }
                name.append(to_string(seq));
                return name;
            }

            Name
            Drop::makeDiscoverName(uint64_t seq) const {
                Name name("ndn/broadcast/drop/discover");
                name.append(m_options.home_name);
                name.append(m_options.node_name);
                if (!m_options.clientIdentifier.empty()) {
                    name.append(m_options.clientIdentifier);
                }
                name.append(to_string(seq));
                return name;
            }

            void
            Drop::handleData(const Interest&, const Data& data)
            {
                const Block& content = data.getContent();
                std::string val = std::string(content.value(), content.value() + content.value_size());
                if (debug == true) {
                    std::cout << "Received a discover reply: " << data << std::endl;
                    std::cout << val.length() << endl;
                    std::cout << "Content: " << val << endl;
                }
                neighborListLock.lock();
                neighborList.deserializeList(val);
                neighborListLock.unlock();
            }

        } // namespace client
    } // namespace drop
} // namespace ndn
