#include "core/version.hpp"
#include <iostream>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <fstream>
#include <sstream>
#include <ndn-cxx/security/transform/private-key.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/base64-decode.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include "../crypto/data-enc-dec.hpp"
#include "../crypto/rsa.hpp"

namespace ndn {
namespace chunks {

static int
main(int argc, char* argv[])
{
     std::vector<u_int8_t> beg2;
  //find a way to make this more dynamic
  std::ifstream k ("../ndn-drop/key.ndn");
    k >> std::noskipws;
    uint8_t c;
    while (k >> c){
      beg2.push_back(c);
    }
    k.close();

    std::vector<u_int8_t> payload;
    std::ifstream inputFile (argv[1]);
    inputFile >> std::noskipws;
    uint8_t ch;
    while (inputFile >> ch){
      payload.push_back(ch);
    }
    inputFile.close();

    Block data(payload.data(), payload.size());

    auto decryptedData = decryptDataContent(data, beg2.data(), beg2.size());
    std::ofstream outFile;
    outFile.open(argv[1]);
    const char* beg = (char *) (decryptedData.data());
    const int end =  decryptedData.size();
    outFile.write(beg, end);
    // size_t i = 0;
    // for (; beg != end; ++beg, ++i)
    // {
    //     std::cout <<  (*beg);
    // }
    outFile.close();
    return 0;
}

}
}


int
main(int argc, char* argv[])
{
  return ndn::chunks::main(argc, argv);
}
