//
// Created by NIshant Sabharwal on 5/15/20.
//

#include "neighbor_list.hpp"
#include <sstream>
#include <fstream>
#include <cstdio>

using namespace std;

void
NeighborList::addNeighbor(std::string neighborName) {
    neighborList[neighborName] = neighborListLifetime;
}

void
NeighborList::decrementList() {
    for (auto it = neighborList.begin(); it != neighborList.end(); ) {
        if (it->second > 0) {
            it->second--;
            it++;
        }
        else {
            it = neighborList.erase(it);
        }
    }
    std::string tmpFileName = neighborFile + ".tmp";
    std::ofstream tmpFile(tmpFileName, std::ofstream::trunc);
    tmpFile << serializeList();
    tmpFile.close();
    if (std::rename(tmpFileName.c_str(), neighborFile.c_str()) < 0) {
        std::cout << strerror(errno) << '\n';
    }
    if (debug) {
        printf("Current neighbor list: \n");
        for (auto x : neighborList) {
            cout << x.first << ": " << x.second << endl;
        }
        printf("\n");
    }
}

std::vector<std::string>
NeighborList::split (const std::string &s, char delim) {
    std::vector<string> result;
    std::stringstream ss (s);
    std::string item;

    while (getline (ss, item, delim)) {
        result.push_back (item);
    }

    return result;
}

std::string
NeighborList::serializeList() {
    std::stringstream ss;
    for (auto x : neighborList) {
        ss << x.first << ":" << x.second << "\n";
    }
    std::string serialized = ss.str();
    if (serialized.length() > 0) {
        serialized.pop_back();
    }
    return serialized;
};

void
NeighborList::deserializeList(std::string blob) {
    if (blob.length() == 0) {
        return;
    }
    std::vector<std::string> blobs = split(blob, '\n');
    for (int i=0; i<blobs.size(); i++) {
        std::vector<std::string> nameCount = split(blobs[i], ':');
        if (nameCount.size() == 2) {
            addNeighbor(nameCount[0]);
        }
    }
};

NeighborList::NeighborList (int heartbeatWindow) {
    neighborListHeartbeatWindow = heartbeatWindow;
}