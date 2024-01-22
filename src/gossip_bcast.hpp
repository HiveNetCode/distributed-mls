/**
 * @file gossip_bcast.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Handling of Gossip Broadcast instance to deliver proposals and app messages
 *  Uses the Murmur protocol from 'R. Guerraoui et al. Scalable Byzantine Reliable Broadcast'
 */

#ifndef __GOSSIP_BCAST_HPP__
#define __GOSSIP_BCAST_HPP__

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <iterator>
#include <random>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "bytes/bytes.h"
#include "mls/crypto.h"

#include "dds_message.hpp"
#include "extended_mls_state.hpp"
#include "network.hpp"

using DeliverCallback = std::function<void(const mls::MLSMessage & msg)>;

class GossipBcast
{
public:
    GossipBcast(Network & network, const mls::bytes_ns::bytes & selfId,
        const mls::CipherSuite & suite, const DeliverCallback & deliver)
        : m_network(network), m_selfId(selfId), m_suite(suite), m_deliver(deliver)
    { }

    void init(const ExtendedMLSState & state)
    {
        updateSample(state);
        computeSample();
    }

    void newEpoch(const ExtendedMLSState & state, const std::vector<mls::bytes_ns::bytes> & removed)
    {
        m_received.clear();

        bool updated = false;
        for(const auto & id : removed)
            if(m_idsSample.contains(id))
            {
                updated = true;
                m_idsSample.erase(id);
            }

        if(updateSample(state) || updated)
            computeSample();
    }

    void receiveMessage(const GossipBcastMessage & msg)
    {
        if(msg.isGossip())
        {
            if(!m_received.contains(m_suite.ref(msg.bcastMessage())))
            {
                dispatchMessage(msg.bcastMessage()); // Dispatch includes delivery to client
            }
        }
        else if(msg.isSubscribe())
        {
            if(!m_idsSample.contains(msg.subscriberId()))
            {
                std::string strId = {msg.subscriberId().data(),
                    msg.subscriberId().data() + msg.subscriberId().size()};
                
                m_idsSample.insert(msg.subscriberId());
                m_computedSample.emplace_back(strId);

                for(const auto & msg : m_received)
                    m_network.send(strId, msg.second);
            }
        }
    }

    void dispatchMessage(const mls::MLSMessage & msg)
    {
        DDSMessage ddsMsg = {
            .content = { (GossipBcastMessage) {
                .content = { msg }
            }}
        };

        Bytes messageBytes = marshalToBytes(ddsMsg);
        m_received.insert({m_suite.ref(msg), messageBytes});
        m_network.broadcastSample(m_computedSample, messageBytes);

        m_deliver(msg);
    }

    static constexpr int MINIMUM_PEERS = 6;

protected:
    bool updateSample(const ExtendedMLSState & state)
    {
        const auto members = state.getMembersIdentity(true);
        const size_t expectedMin = std::max<int>(
            std::log10(members.size()), MINIMUM_PEERS);

        if(m_idsSample.size() < expectedMin && m_idsSample.size() < members.size())
        {
            std::set<mls::bytes_ns::bytes> difference, sample;

            // Who is not in my sample
            std::set_difference(members.begin(), members.end(),
                m_idsSample.begin(), m_idsSample.end(),
                std::inserter(difference, difference.begin()));

            // Sample through those candidates
            std::sample(difference.begin(), difference.end(),
                std::inserter(sample, sample.begin()),
                std::min(difference.size(), expectedMin - m_idsSample.size()),
                std::mt19937{std::random_device{}()});

            for(const auto & sampled : sample)
            {
                subscribe(sampled);
                m_idsSample.insert(sampled);
            }

            return true;
        }
        return false;
    }

    void subscribe(const mls::bytes_ns::bytes & id)
    {
        DDSMessage msg = {
            .content = { (GossipBcastMessage) {
                .content = { m_selfId }
            }}
        };

        m_network.send({id.begin(), id.end()}, marshalToBytes(msg));
    }

    void computeSample()
    {
        m_computedSample.clear();

        for(const auto & id : m_idsSample)
            m_computedSample.emplace_back(
                std::string{(const char *) id.data(), id.size()});
    }

private:
    Network & m_network;
    const mls::bytes_ns::bytes m_selfId;
    const mls::CipherSuite & m_suite;
    const DeliverCallback m_deliver;

    std::vector<std::string> m_computedSample;
    std::set<mls::bytes_ns::bytes> m_idsSample;

    std::map<MessageRef, Bytes> m_received;

};

#endif
