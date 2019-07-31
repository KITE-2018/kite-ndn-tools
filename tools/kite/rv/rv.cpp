/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015-2019, Harbin Institute of Technology.
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
 * @author Zhongda Xia <xiazhongda@hit.edu.cn>
 */

#include "rv.hpp"

#include <ndn-cxx/kite/ack.hpp>
#include <ndn-cxx/kite/request.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/logger.hpp>

namespace ndn {
namespace kite {
namespace rv {

NDN_LOG_INIT(kite.rv);

const char* CONF_PATH = "/home/charlie/ndn/misc/rv.conf";

Rv::Rv(Face& face, KeyChain& keyChain, const Options& options)
  : m_options(options)
  , m_face(face)
  , m_keyChain(keyChain)
  , m_validator(face)
{
  m_validator.load(CONF_PATH);
}

void
Rv::start()
{
  m_registeredPrefix = m_face.setInterestFilter(
                       Name(m_options.prefixes[0]),
                       bind(&Rv::onInterest, this, _2),
                       [] (const auto&, const auto& reason) {
                         NDN_THROW(std::runtime_error("Failed to register prefix: " + reason));
                       });
}

void
Rv::stop()
{
  m_registeredPrefix.unregister();
}


void
Rv::onInterest(const Interest& interest)
{
  afterReceive(interest.getName());

  m_validator.validate(interest,
                       std::bind(&Rv::onSuccess, this, _1),
                       std::bind(&Rv::onFailure, this, _1, _2));
}

void
Rv::onSuccess(const Interest& interest)
{
  NDN_LOG_DEBUG("Verification success for: " << interest.getName());

  Request req(interest);
  Ack ack;
  PrefixAnnouncement pa;
  pa.setAnnouncedName(req.getProducerPrefix());
  if (req.getExpiration()) {
    NDN_LOG_DEBUG("Has expiration: " << std::to_string(req.getExpiration()->count()) << " ms");
    pa.setExpiration(*req.getExpiration());
  }
  else {
    NDN_LOG_DEBUG("Expiration not set, setting to 1000 ms...");
    pa.setExpiration(1000_ms);
  }

  ack.setPrefixAnnouncement(pa);

  m_face.put(ack.makeData(interest, m_keyChain, ndn::security::signingByIdentity(m_options.prefixes[0])));
}

void
Rv::onFailure(const Interest& interest, const ValidationError& error)
{
  NDN_LOG_DEBUG("Verification failure for: " << interest.getName() << "\nError: " << error);
}

} // namespace server
} // namespace ping
} // namespace ndn
