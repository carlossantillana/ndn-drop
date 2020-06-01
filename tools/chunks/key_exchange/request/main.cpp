#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <boost/asio/io_service.hpp>
#include <functional>
#include <iostream>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <thread>
#include <fstream>

using namespace ndn;
using namespace std;

class KeyRequestor {
public:
    KeyRequestor(string identity1, string requestingKey1, string outfile1)
            : m_face(m_ioService),
              m_scheduler(m_ioService)
    {
        identity = identity1;
        requestingKey = requestingKey1;
        outfile = outfile1;
    }

    void
    run()
    {
        m_thread = thread(&KeyRequestor::publicKeyRequestListener, this);
        Interest::setDefaultCanBePrefix(true);
        restart();
        m_ioService.run();
    }

private:
    void publicKeyRequestListener() {
        cout << "setting prefix for " << identity + "/KEY" << endl;
        m_face.registerPrefix(identity + "/KEY", RegisterPrefixSuccessCallback(),
                              bind(&KeyRequestor::onRegisterFailed, this, _1, _2));
        m_face.setInterestFilter(identity + "/KEY",
                                 std::bind(&KeyRequestor::onPublicKeyInterest, this, _2));
        m_face.processEvents();
        cout << "goodbye" << endl;
    }

    void
    onPublicKeyInterest(const Interest& interest) {
        string desiredCert = interest.getName().toUri();
        cout << "Got an interest for my certificate: " << desiredCert << endl;

        string certName = m_keyChain.getPib().getIdentity(identity).getDefaultKey().getDefaultCertificate().getName().toUri();
        cout << certName << " " << desiredCert << endl;
        if (certName != desiredCert) {
            cout << "Uh oh: non-existent key!" << endl;
            return;
        }

        ndn::security::v2::Certificate cert = m_keyChain.getPib().getIdentity("/ndn/drop/nishant/laptop").getDefaultKey().getDefaultCertificate();
        m_face.put(cert);
    }

    void
    onRegisterFailed(const Name& prefix, const std::string& reason)
    {
        std::cerr << "ERROR: Failed to register prefix \"" << prefix
                  << "\" in local hub's daemon (" << reason << ")" << std::endl;
        m_face.shutdown();
    }

    void
    requestSessionKey()
    {
        std::cout << "\n******\nStart a new loop." << std::endl;
        Name sessionKeyDataName = makeSessionKeyName(requestingKey);
        Interest interest(sessionKeyDataName); // bedroom current temperature content
        interest.setMustBeFresh(true);
        interest.setCanBePrefix(true);

        string keyName = m_keyChain.getPib().getIdentity(identity).getDefaultKey().getName().toUri();
        string certName = m_keyChain.getPib().getIdentity(identity).getDefaultKey().getDefaultCertificate().getName().toUri();
        string param = certName;

        const uint8_t* value = reinterpret_cast<const uint8_t*>(&param[0]);
        interest.setApplicationParameters(value, param.length());


        cout << "Sending an interest for: " << interest.getName().toUri() << endl;

        m_keyChain.sign(interest, security::signingByIdentity(Name(identity)));
        m_face.expressInterest(interest,
                               bind(&KeyRequestor::afterGetSessionKey, this, _2),
                               bind([this] { onNack(); }),
                               bind([this] { onTimeout(); }));
    }

    void
    afterGetSessionKey(const Data &data)
    {
        cout << "Got session key:" << data.getName().toUri() << endl;

        Name localKeyName = m_keyChain.getPib().getIdentity(identity).getDefaultKey().getName();
        ConstBufferPtr buf = m_keyChain.getTpm().decrypt(data.getContent().value(), data.getContent().value_size(),  localKeyName);
        cout << "Decrypted file. Before: " << data.getContent().size() << " bytes. After: " << buf->size() << " bytes." << endl;

        cout << "Saving session key to " << outfile << endl;

        ofstream fout;
        fout.open(outfile, ios::binary | ios::out);
        fout.write((char*) (char *)buf->get<uint8_t>(), buf->size());
        fout.close();

    }

    void
    restart()
    {
        std::cout << "Start to wait 3s..." << std::endl;
        m_scheduler.schedule(3_s, bind(&KeyRequestor::requestSessionKey, this));
    }

    void
    onNack()
    {
        std::cout << "got a NACK" << std::endl;
        restart();
    }

    void
    onTimeout()
    {
        std::cout << "got a timeout" << std::endl;
        restart();
    }

    Name
    makeSessionKeyName(string keyName) const {
        Name name("ndn/drop/session_key");
        cout << "making key" << keyName << endl;
        //name.append(keyName);
        return name.append(keyName);
    }

private:
    boost::asio::io_service m_ioService;
    Face m_face;
    Scheduler m_scheduler;
    KeyChain m_keyChain;
    string requestKeyName;
    string identity;
    string requestingKey;
    thread m_thread;
    string outfile;
};

int
main(int argc, char* argv[])
{
    if (argc != 4) {
        cout << "Usage: ./key_exchange identity requested_key outfile" << endl;
        return 0;
    }
    string identity = argv[1];
    string requested_key = argv[2];
    string outfile = argv[3];
    KeyRequestor app(identity, requested_key, outfile);
    try {
        app.run();
    }
    catch (const std::exception &e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
    return 0;
}