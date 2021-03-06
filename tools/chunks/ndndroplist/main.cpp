/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016-2019, Regents of the University of California,
 *                          Colorado State University,
 *                          University Pierre & Marie Curie, Sorbonne University.
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
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 *
 * @author Wentao Shang
 * @author Steve DiBenedetto
 * @author Andrea Tosatto
 * @author Davide Pesavento
 * @author Klaus Schneider
 */

#include "core/version.hpp"
#include "producer.hpp"
#include <iostream>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <fstream>
#include <sstream>
#include <ndn-cxx/security/transform/private-key.hpp>
#include <ndn-cxx/security/transform/private-key.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/base64-decode.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include "../crypto/data-enc-dec.hpp"
#include "../crypto/rsa.hpp"
namespace po = boost::program_options;

namespace ndn {
namespace chunks {

static void
usage(std::ostream& os, const std::string& programName, const po::options_description& desc)
{
  os << "Usage: " << programName << " [options] ndn:/name\n"
     << "\n"
     << "Publish data under the specified prefix.\n"
     << "Note: this tool expects data from the standard input.\n"
     << "\n"
     << desc;
}

static int
main(int argc, char* argv[])
{
  std::string programName = argv[0];
  std::string prefix;
  std::string signingStr;
  Producer::Options opts;
  std::string ndnDropLink;

  po::options_description visibleDesc("Options");
  visibleDesc.add_options()
    ("help,h",          "print this help message and exit")
    ("freshness,f",     po::value<time::milliseconds::rep>()->default_value(opts.freshnessPeriod.count()),
                        "FreshnessPeriod of the published Data packets, in milliseconds")
    ("print-data-version,p", po::bool_switch(&opts.wantShowVersion),
                             "print Data version to the standard output")
    ("size,s",          po::value<size_t>(&opts.maxSegmentSize)->default_value(opts.maxSegmentSize),
                        "maximum chunk size, in bytes")
    ("signing-info,S",  po::value<std::string>(&signingStr), "see 'man ndnputchunks' for usage")
    ("quiet,q",         po::bool_switch(&opts.isQuiet), "turn off all non-error output")
    ("verbose,v",       po::bool_switch(&opts.isVerbose), "turn on verbose output (per Interest information)")
    ("version,V",       "print program version and exit")
    ;

  po::options_description hiddenDesc;
  hiddenDesc.add_options()
    ("ndn-name,n", po::value<std::string>(&prefix), "NDN name for the served content");
  hiddenDesc.add_options()
    ("ndn-drop-dir,d", po::value<std::string>(&ndnDropLink), "NDN Drop directory for the served content");

  po::positional_options_description p;
  p.add("ndn-name", -1);
  p.add("ndn-drop-dir", -1);

  po::options_description optDesc;
  optDesc.add(visibleDesc).add(hiddenDesc);

  po::variables_map vm;
  try {
    po::store(po::command_line_parser(argc, argv).options(optDesc).positional(p).run(), vm);
    po::notify(vm);
  }
  catch (const po::error& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 2;
  }
  catch (const boost::bad_any_cast& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 2;
  }

  if (vm.count("help") > 0) {
    usage(std::cout, programName, visibleDesc);
    return 0;
  }

  if (vm.count("version") > 0) {
    std::cout << "ndnputchunks " << tools::VERSION << std::endl;
    return 0;
  }

  if (prefix.empty()) {
    usage(std::cerr, programName, visibleDesc);
    return 2;
  }

  opts.freshnessPeriod = time::milliseconds(vm["freshness"].as<time::milliseconds::rep>());
  if (opts.freshnessPeriod < 0_ms) {
    std::cerr << "ERROR: FreshnessPeriod cannot be negative" << std::endl;
    return 2;
  }

  if (opts.maxSegmentSize < 1 || opts.maxSegmentSize > MAX_NDN_PACKET_SIZE) {
    std::cerr << "ERROR: Maximum chunk size must be between 1 and " << MAX_NDN_PACKET_SIZE << std::endl;
    return 2;
  }

  try {
    opts.signingInfo = security::SigningInfo(signingStr);
  }
  catch (const std::invalid_argument& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 2;
  }

  if (opts.isQuiet && opts.isVerbose) {
    std::cerr << "ERROR: Cannot be quiet and verbose at the same time" << std::endl;
    return 2;
  }
  std::cout << "path:  " << ndnDropLink << std::endl;
    boost::filesystem::path pa (ndnDropLink);

    boost::filesystem::directory_iterator end_itr;

    // cycle through the directory
  boost::thread_group group;
  std::vector<Producer*> producers;
  std::vector<std::string> outputFileNames;
  std::vector<Face*> faces;
  std::vector<KeyChain*> keyChains;
  std::vector<std::ifstream*> inFiles;
  const std::string cipherTextBase64 = 
  "MIICXAIBAAKBgQC7qlkrJvhJo+nwRpJEevpc4BFxTNXZlgUo4Jb9ewEQbm9qQCEZ\n"
"drZXoCNuwtDamCvypyGaKKHp+zu8IOYu4TtVyb26tB1DOieBwhQ2QEYjhOquWFvT\n"
"GJ0udph0KKB8d1tb0SZxBUg8EhrwQSw5cdoZTI4jYo2pNNEtGgGPlkRUxwIDAQAB\n"
"AoGBAKUhMNMSuFj7/YZqYpwVZiXBGDgM9wM9yY59iP7EdFxEAI+KnFVuquYRx/vX\n"
"OrWOPuWGgL/ITyi244oXnNPVZkIDkVOG6JICMrfxQYsFtS7NeG1jcKwS5L9NhMTQ\n"
"QczO/m+6cgcqKnIhxHz+jOesHCJMKwNPO2d3K8H0L89HqYoRAkEA8+VUB8eoquJj\n"
"yXuiS/toCu8nIz4k3tOg8Q0Nc25ylTdZ2ivw/HaqTUP7N7AFvb6Sw5bSoknNIR44\n"
"Ks3O5eqOrwJBAMT6nl4K9SYNJoMqfvEpTD9Wr1o8p9Sl4eAtM9+cLVT5kcMw4g/R\n"
"EQLU28OZF4FSsM8XjkmJrFNThmamo6LY4WkCQFHcnljCJhW9SPr+mVnhd2l8HenR\n"
"WPTFmZZu6B3fa2w0GN+Gsis69Sxb7f0iArtONNqbS/WWydgc2YNcct5u3RcCQErI\n"
"XzGS9Wlh2ro3ewQxypnNXjtjBdCsvalvX99IGsnFCjrRpzGcDNpHV7vVtl/JtgiZ\n"
"h9KRaxQjhMYaA8wCjOkCQA5dhqhtq3WsgwCiQQ/UxPk8oJxUuBs33+zNSX+I34ac\n"
"szAH0qxEJHJvDCtCLUbc3FVdbRkZ7mBCzL374RlfDss=\n";

  size_t keyLen = 1024;
  Buffer data = Buffer(reinterpret_cast<const uint8_t*>(cipherTextBase64.data()), keyLen);

  int j = 0;
    for (boost::filesystem::directory_iterator itr(pa); itr != end_itr; ++itr)
    {
        // If it's not a directory, list it. If you want to list directories too, just remove this check.
        if (boost::filesystem::is_regular_file(itr->path())) {
            // assign current file name to current_file and echo it out to the console.
            std::string current_file = itr->path().string();
            std::cout << current_file << std::endl;
            outputFileNames.push_back(current_file);
            std::string delimiter = "/";
            size_t pos = 0;
            std::string token;
            while ((pos = outputFileNames[j].find(delimiter)) != std::string::npos) {
              outputFileNames[j].erase(0, pos + delimiter.length());
            }
            try {
              outputFileNames[j].insert(0, prefix);
              std::ifstream *inFile = new std::ifstream;
              inFiles.push_back(inFile);
              inFiles[j]->open(current_file);
              Face *face = new Face();
              faces.push_back(face);
              KeyChain *keyChain = new KeyChain();
              keyChains.push_back(keyChain);
              producers.push_back(new Producer(outputFileNames[j], *faces[j], *keyChains[j], *inFiles[j], opts, data));
              j++;
            }
            catch (const std::exception& e) {
              std::cerr << "ERROR: " << e.what() << std::endl;
              return 1;
            }
        }
    }
    for (auto p : producers){
      boost::thread *t = group.create_thread(boost::bind(&Producer::run, p));
    }
    group.join_all();
  return 0;
}

} // namespace chunks
} // namespace ndn

int
main(int argc, char* argv[])
{
  return ndn::chunks::main(argc, argv);
}
