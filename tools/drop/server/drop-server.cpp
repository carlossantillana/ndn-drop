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
 * @author Eric Newberry <enewberry@email.arizona.edu>
 * @author Jerald Paul Abraham <jeraldabraham@email.arizona.edu>
 */

#include "drop-server.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndn {
namespace drop {
namespace server {

DropServer::DropServer(Face& face, KeyChain& keyChain, const Options& options)
  : m_options(options)
  , m_face(face)
  , m_keyChain(keyChain)
  , m_nDrops(0)
{
  auto b = make_shared<Buffer>();
  b->assign(m_options.payloadSize, 'a');
  m_payload = Block(tlv::Content, std::move(b));
}

void
DropServer::start()
{
    m_registeredPrefix = m_face.setInterestFilter(
                       Name(m_options.prefix).append("drop"),
                       bind(&DropServer::onInterest, this, _2),
                       [] (const auto&, const auto& reason) {
                         NDN_THROW(std::runtime_error("Failed to register prefix: " + reason));
                       });
    m_registeredPrefix2 = m_face.setInterestFilter(
            Name("/ndn/broadcast").append("drop"),
            bind(&DropServer::onInterest2, this, _2),
            [] (const auto&, const auto& reason) {
                NDN_THROW(std::runtime_error("Failed to register prefix: " + reason));
            });

}

void
DropServer::stop()
{
  m_registeredPrefix.cancel();
  m_registeredPrefix2.cancel();
}

size_t
DropServer::getNDrops() const
{
  return m_nDrops;
}

void
DropServer::onInterest(const Interest& interest)
{
  afterReceive(interest.getName());
  std::cout << interest.getName() << std::endl;

  auto data = make_shared<Data>(interest.getName());
  data->setFreshnessPeriod(m_options.freshnessPeriod);
  data->setContent(m_payload);
  m_keyChain.sign(*data, signingWithSha256());
  m_face.put(*data);

  ++m_nDrops;
  if (m_options.nMaxDrops > 0 && m_options.nMaxDrops == m_nDrops) {
    afterFinish();
  }
}

    void
    DropServer::onInterest2(const Interest& interest)
    {
        afterReceive(interest.getName());
        std::cout << "second" << std::endl;
        std::cout << interest.getName() << std::endl;

        auto data = make_shared<Data>(interest.getName());
        data->setFreshnessPeriod(m_options.freshnessPeriod);
        data->setContent(m_payload);
        m_keyChain.sign(*data, signingWithSha256());
        m_face.put(*data);

        ++m_nDrops;
        if (m_options.nMaxDrops > 0 && m_options.nMaxDrops == m_nDrops) {
            afterFinish();
        }
    }

} // namespace server
} // namespace drop
} // namespace ndn
