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

namespace ndn {
namespace drop {
namespace client {

Drop::Drop(Face& face, const Options& options)
  : m_options(options)
  , m_nSent(0)
  , m_nextSeq(options.startSeq)
  , m_nOutstanding(0)
  , m_face(face)
  , m_scheduler(m_face.getIoService())
{
  if (m_options.shouldGenerateRandomSeq) {
    m_nextSeq = random::generateWord64();
  }
}

void
Drop::start()
{
  performDrop();
}

void
Drop::stop()
{
  m_nextDropEvent.cancel();
}

void
Drop::performDrop()
{
  BOOST_ASSERT((m_options.nDrops < 0) || (m_nSent < m_options.nDrops));

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
    m_nextDropEvent = m_scheduler.schedule(m_options.interval, [this] { performDrop(); });
  }
  else {
    finish();
  }
}

void
Drop::onData(uint64_t seq, const time::steady_clock::TimePoint& sendTime)
{
  time::nanoseconds rtt = time::steady_clock::now() - sendTime;
  afterData(seq, rtt);
  finish();
}

void
Drop::onNack(const lp::Nack& nack, uint64_t seq, const time::steady_clock::TimePoint& sendTime)
{
  time::nanoseconds rtt = time::steady_clock::now() - sendTime;
  afterNack(seq, rtt, nack.getHeader());
  finish();
}

void
Drop::onTimeout(uint64_t seq)
{
  afterTimeout(seq);
  finish();
}

void
Drop::finish()
{
  if (--m_nOutstanding >= 0) {
    return;
  }
  afterFinish();
}

Name
Drop::makeDropName(uint64_t seq) const
{
  Name name(m_options.prefix);
  name.append("drop");
  if (!m_options.clientIdentifier.empty()) {
    name.append(m_options.clientIdentifier);
  }
  name.append(to_string(seq));
  return name;
}

} // namespace client
} // namespace drop
} // namespace ndn
