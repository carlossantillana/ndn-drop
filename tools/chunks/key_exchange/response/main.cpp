#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fstream>
#include <functional>
#include <iostream>
#include <ndn-cxx/face.hpp>
#include <string>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/security/v2/validator.hpp>
#include <ndn-cxx/security/v2/validation-callback.hpp>
#include <ndn-cxx/security/v2/certificate-fetcher-offline.hpp>
#include <ndn-cxx/security/v2/certificate-fetcher-from-network.hpp>
#include <ndn-cxx/security/v2/certificate-fetcher.hpp>
#include <ndn-cxx/security/v2/certificate-fetcher-direct-fetch.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>


using namespace ndn;
using namespace std;
using namespace ndn::security::transform;

const std::string prefix = "/ndn/drop/session_key";
const std::string device_id = "/bedroom/aircon-1";

class KeyResponder {
public:
    KeyResponder(string pathToKeyDir1, string identity1, string pathToTrustAnchor1) : m_state("off")
    {
        pathToKeyDir = pathToKeyDir1;
        identity = identity1;
        pathToTrustAnchor = pathToTrustAnchor1;
    }

    void
    run()
    {
        m_face.registerPrefix(prefix, RegisterPrefixSuccessCallback(),
                              bind(&KeyResponder::onRegisterFailed, this, _1, _2));
        m_face.setInterestFilter(prefix,
                                 std::bind(&KeyResponder::onInterest, this, _2));
        m_face.processEvents();
    }

private:

    void
    onNack()
    {
        std::cout << "got a NACK" << std::endl;
    }

    void
    onTimeout()
    {
        std::cout << "got a timeout" << std::endl;
    }

    vector<std::string>
    split (const std::string &s, char delim) {
        vector<string> result;
        stringstream ss (s);
        string item;

        while (getline (ss, item, delim)) {
            result.push_back (item);
        }

        return result;
    }

    void
    onInterest(const Interest& interest)
    {
        cout << "Got an interest: " << interest.getName().toUri() << endl;
        if (interest.getName().size() < 7) {
            cout << "Poorly formatted name: " << interest.getName().toUri() << endl;
            return;
        }
        const Block& param = interest.getApplicationParameters();
        std::string certName = std::string(param.value(), param.value() + param.value_size());

        // Make sure this node is trusted
        Name signingCertName = Name(certName);
        Interest keyInterest(signingCertName);
        keyInterest.setMustBeFresh(true);
        keyInterest.setCanBePrefix(true);

        cout << "sending interest to get certificate for " << keyInterest.getName().toUri() << endl;

        m_face.expressInterest(keyInterest,
                               bind(&KeyResponder::afterKeyInterest, this, _2, interest),
                               bind([this] { onNack(); }),
                               bind([this] { onTimeout(); }));
    }

    bool verifyAgainstTrustAnchor(const Data &data) {
        uint8_t pk_bits[1000];
        std::ifstream infile(pathToTrustAnchor, ofstream::binary);
        infile.seekg(0, std::ios::end);
        size_t length = infile.tellg();
        infile.seekg(0, std::ios::beg);
        infile.read((char*) pk_bits, length);
        infile.close();

        return security::verifySignature(data, pk_bits, length);
    }

    void afterKeyInterest(const Data &data, Interest& originalInterest) {

        cout << "Received data packet for Certificate: " << data.getName().toUri() << endl;
        Block blk = data.getContent();
        const uint8_t *buf = reinterpret_cast<const uint8_t*>(blk.value());

        // Verify original interest
        cout << "Verifying original interest: " << originalInterest.getName().toUri() << endl;
        bool passed = security::verifySignature(originalInterest, buf, blk.value_size());
        if (passed == false) {
            cout << "Verification failed!" << endl;
            lp::Nack nack(originalInterest);
            m_face.put(nack);
            return;
        }
        cout << "This public key did indeed sign the original interest!" << endl;

        bool publicKeyVerified = verifyAgainstTrustAnchor(data);

        if (publicKeyVerified == false) {
            cout << "Verification of public key failed!" << endl;
            lp::Nack nack(originalInterest);
            m_face.put(nack);
            return;
        }
        cout << "This public key is indeed signed by our trust anchor!" << endl;

        // Find whatever session key they're asking for
        string requestedKeyName = pathToKeyDir + "/" + originalInterest.getName()[5].toUri() + "_" + originalInterest.getName()[6].toUri() + ".key";
        cout << "Encrypting " << requestedKeyName << endl;
        uint8_t requestedKeyBits[1000];
        std::ifstream requestedKeyFile(requestedKeyName, ofstream::binary);
        if (requestedKeyFile.fail()) {
            cout << "Problem opening " << requestedKeyName << endl;
            return;
        }
        requestedKeyFile.seekg(0, std::ios::end);
        size_t requestedKeyLength = requestedKeyFile.tellg();
        requestedKeyFile.seekg(0, std::ios::beg);
        requestedKeyFile.read((char*) requestedKeyBits, requestedKeyLength);

        cout << "Starting encryption" << endl;
        PublicKey consumerPublicKey;
        consumerPublicKey.loadPkcs8(buf, blk.value_size());
        ConstBufferPtr encryptedBits = consumerPublicKey.encrypt(requestedKeyBits, requestedKeyLength);

        Data dataEncrypted(originalInterest.getName());
        dataEncrypted.setFreshnessPeriod(10_ms);
        dataEncrypted.setContent(encryptedBits->get<uint8_t>(),
                                 encryptedBits->size());
        m_keyChain.sign(dataEncrypted);
        m_face.put(data);
        cout << "Responding to orignal interest with data: " << dataEncrypted.getName().toUri() << endl;
        m_face.put(dataEncrypted);
        cout << endl;

    }

    void
    onRegisterFailed(const Name& prefix, const std::string& reason)
    {
        std::cerr << "ERROR: Failed to register prefix \"" << prefix
                  << "\" in local hub's daemon (" << reason << ")" << std::endl;
        m_face.shutdown();
    }

private:
    Face m_face;
    KeyChain m_keyChain;
    std::string m_state;
    string pathToKeyDir;
    string identity;
    string pathToTrustAnchor;
};

int
main(int argc, char* argv[])
{
    if (argc != 4) {
        cout << "Usage: ./key_exchange path_to_key_dir identity path_to_trust_anchor_pub_key" << endl;
        return 0;
    }
    string path_to_key_dir = argv[1];
    string identity = argv[2];
    string trustAnchorPubKey = argv[3];
    KeyResponder app(path_to_key_dir, identity, trustAnchorPubKey);
    try {
        app.run();
    }
    catch (const std::exception &e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
    return 0;
}