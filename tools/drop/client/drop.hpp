/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015-2019,  Arizona Board of Regents.
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

#ifndef NDN_TOOLS_DROP_CLIENT_DROP_HPP
#define NDN_TOOLS_DROP_CLIENT_DROP_HPP

#include "core/common.hpp"

namespace ndn {
namespace drop {
namespace client {

typedef time::duration<double, time::milliseconds::period> Rtt;

/**
 * @brief options for ndndrop client
 */
struct Options
{
  Name prefix;                      //!< prefix droped
  bool shouldAllowStaleData;        //!< allow stale Data
  bool shouldGenerateRandomSeq;     //!< random drop sequence
  bool shouldPrintTimestamp;        //!< print timestamp
  int nDrops;                       //!< number of drops
  time::milliseconds interval;      //!< drop interval
  time::milliseconds timeout;       //!< timeout threshold
  uint64_t startSeq;                //!< start drop sequence number
  name::Component clientIdentifier; //!< client identifier
};

/**
 * @brief NDN modular drop client
 */
class Drop : noncopyable
{
public:
  Drop(Face& face, const Options& options);

  /**
   * @brief Signals on the successful return of a Data packet
   *
   * @param seq drop sequence number
   * @param rtt round trip time
   */
  signal::Signal<Drop, uint64_t, Rtt> afterData;

  /**
   * @brief Signals on the return of a Nack
   *
   * @param seq drop sequence number
   * @param rtt round trip time
   * @param header the received Network NACK header
   */
  signal::Signal<Drop, uint64_t, Rtt, lp::NackHeader> afterNack;

  /**
   * @brief Signals on timeout of a packet
   *
   * @param seq drop sequence number
   */
  signal::Signal<Drop, uint64_t> afterTimeout;

  /**
   * @brief Signals when finished droping
   */
  signal::Signal<Drop> afterFinish;

  /**
   * @brief Start sending drop interests
   *
   * @note This method is non-blocking and caller need to call face.processEvents()
   */
  void
  start();

  /**
   * @brief Stop sending drop interests
   *
   * This method cancels any future drop interests and does not affect already pending interests.
   *
   * @todo Cancel pending drop interest
   */
  void
  stop();

private:
  /**
   * @brief Creates a drop Name from the sequence number
   *
   * @param seq drop sequence number
   */
  Name
  makeDropName(uint64_t seq) const;

  /**
   * @brief Performs individual drop
   */
  void
  performDrop();

  /**
   * @brief Called when a Data packet is received in response to a drop
   *
   * @param seq drop sequence number
   * @param sendTime time drop sent
   */
  void
  onData(uint64_t seq, const time::steady_clock::TimePoint& sendTime);

  /**
   * @brief Called when a Nack is received in response to a drop
   *
   * @param interest NDN interest
   * @param nack returned nack
   * @param seq drop sequence number
   * @param sendTime time drop sent
   */
  void
  onNack(const lp::Nack& nack, uint64_t seq,
         const time::steady_clock::TimePoint& sendTime);

  /**
   * @brief Called when drop timed out
   *
   * @param interest NDN interest
   * @param seq drop sequence number
   */
  void
  onTimeout(uint64_t seq);

  /**
   * @brief Called after drop received or timed out
   */
  void
  finish();

private:
  const Options& m_options;
  int m_nSent;
  uint64_t m_nextSeq;
  int m_nOutstanding;
  Face& m_face;
  Scheduler m_scheduler;
  scheduler::ScopedEventId m_nextDropEvent;
};

} // namespace client
} // namespace drop
} // namespace ndn

#endif // NDN_TOOLS_DROP_CLIENT_DROP_HPP
