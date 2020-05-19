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

  po::positional_options_description p;
  p.add("ndn-name", -1);

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
    boost::filesystem::path pa ("/home/carlos/Documents/CS217B/ndnDrop");

    boost::filesystem::directory_iterator end_itr;

    // cycle through the directory
      std::vector<boost::thread *> threads;
    for (boost::filesystem::directory_iterator itr(pa); itr != end_itr; ++itr)
    {
        // If it's not a directory, list it. If you want to list directories too, just remove this check.
        if (boost::filesystem::is_regular_file(itr->path())) {
            // assign current file name to current_file and echo it out to the console.
            std::string current_file = itr->path().string();
            std::cout << current_file << std::endl;
            std::string outputFileName = current_file;
            std::string delimiter = "/";
            size_t pos = 0;
            std::string token;
            while ((pos = outputFileName.find(delimiter)) != std::string::npos) {
              outputFileName.erase(0, pos + delimiter.length());
            }
            try {
              outputFileName.insert(0, "/carlos/ndnDrop/");
              std::cout << "prefix: " << outputFileName << std::endl;
              std::ifstream inFile;
              inFile.open(current_file);
              Face face;
              KeyChain keyChain;
              Producer producer(outputFileName, face, keyChain, inFile, opts);
              threads.push_back(new boost::thread(boost::bind(&Producer::run, &producer)));
            }
            catch (const std::exception& e) {
              std::cerr << "ERROR: " << e.what() << std::endl;
              return 1;
            }
        }
    }
  return 0;
}

} // namespace chunks
} // namespace ndn

int
main(int argc, char* argv[])
{
  return ndn::chunks::main(argc, argv);
}