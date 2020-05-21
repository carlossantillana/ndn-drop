//
// Created by NIshant Sabharwal on 5/15/20.
//

#ifndef NDN_DROP_NEIGHBOR_LIST_H
#define NDN_DROP_NEIGHBOR_LIST_H


#include "core/common.hpp"
//#include <pthread.h>

//namespace ndn {
//    namespace drop {
        //namespace client {

            class NeighborList {//: //{//noncopyable {
            public:
                NeighborList(int heartbeatWindow);
                void addNeighbor(std::string neighborName);
                void decrementList();
                std::string serializeList();
                void deserializeList(std::string blob);
                std::vector<std::string> split (const std::string &s, char delim);

            private:
                int neighborListHeartbeatWindow = 3;
                int neighborListLifetime = 3;
                std::unordered_map<std::string, int> neighborList;
                bool debug = true;
                std::string neighborFile = "neighborList.txt";
            };


        //} // namespace client
//    } // namespace drop
//} // namespace ndn

#endif //NDN_DROP_NEIGHBOR_LIST_H

