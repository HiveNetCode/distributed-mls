/**
 * @file distributed_ds.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Implementation of the TreeKEM Distributed Delivery Service
 */

#ifndef __DISTRIBUTED_DS_HPP__
#define __DISTRIBUTED_DS_HPP__

#include <algorithm>
#include <cstdint>
#include <exception>
#include <functional>
#include <iterator>
#include <optional>
#include <ranges>
#include <unordered_map>
#include <vector>

#include "bytes/bytes.h"
#include "mls/common.h"
#include "mls/crypto.h"
#include "mls/messages.h"
#include "mls/tree_math.h"
#include "tls/tls_syntax.h"

#include "cascade_consensus.hpp"
#include "dds_message.hpp"
#include "extended_mls_state.hpp"
#include "gossip_bcast.hpp"
#include "message.hpp"
#include "network.hpp"

using welcomeCallback = std::function<ExtendedMLSState * (const mls::Welcome &)>;
using commitCallback = std::function<ExtendedMLSState * (const mls::MLSMessage &)>;
using messageCallback = std::function<void(const mls::MLSMessage &)>;

// To allow to easily reference commits
template <>
const mls::bytes_ns::bytes & mls::CipherSuite::reference_label<mls::MLSMessage>()
{
    static const auto label = from_ascii("MLS 1.0 Message Reference");
    return label;
}

class DistributedDeliveryService
{
public:
    DistributedDeliveryService(Network & network, int networkRtt,
        const welcomeCallback & receiveWelcome,
        const messageCallback & receiveProposalOrMessage,
        const commitCallback & receiveCommit, const mls::bytes_ns::bytes & selfId,
        const mls::CipherSuite & suite)
        : m_network(network), m_deliverWelcome(receiveWelcome),
            m_deliverProposalOrMessage(receiveProposalOrMessage),
            m_deliverCommit(receiveCommit),
            m_gossipBcast(network, selfId, suite, 
                std::bind(&DistributedDeliveryService::handleGossipDelivery, this, std::placeholders::_1)),
            m_cascadeConsensus(network, networkRtt,
                std::bind(&DistributedDeliveryService::handleCommit, this, std::placeholders::_1),
                std::bind(&DistributedDeliveryService::chooseCommit, this, std::placeholders::_1),
                std::bind(&DistributedDeliveryService::handleConsensusDelivery, this, std::placeholders::_1))
    { }

    void init(ExtendedMLSState * initState)
    {
        state = initState;
        advanceEpoch();

        m_gossipBcast.init(*state);
        m_cascadeConsensus.newEpoch(state);
    }

    void receiveNetworkMessage(const Bytes & rawMessage)
    {
        try
        {
            DDSMessage message;
            mls::tls::unmarshal(std::vector<uint8_t>{rawMessage.content, rawMessage.content + rawMessage.size}, message);

            if(message.isWelcome())
            {
                if(state != nullptr)
                    return; // Invalid already in a group

                init(m_deliverWelcome(message.welcome()));
            }
            else if(message.isGossip())
            {
                m_gossipBcast.receiveMessage(message.gossipMessage());
            }
            else if(message.isCascadeConsensus())
            {
                handleCascadeConsensusReception(message.cascadeConsensusMessage());
            }
        }
        catch(const std::exception & e)
        {
            printf("Received incorrect message: %s\n", e.what());
        }
    }

    void broadcastProposalOrMessage(const mls::MLSMessage & msg)
    {
        if(!state)
            return; // Client Error

        m_gossipBcast.dispatchMessage(msg);
    }

    bool canProposeCommit() const
    {
        return !m_cascadeConsensus.cac1HasStarted();
    }

    void proposeCommit(const mls::MLSMessage & msg, std::optional<mls::Welcome> welcome)
    {
        if(!state)
            return; // Client Error

        m_proposedCommit = { msg };
        m_associatedWelcome = welcome;

        m_cascadeConsensus.proposeCommit(msg);
    }

protected:
    void sendWelcome(const std::vector<mls::bytes_ns::bytes> & added,
        const mls::Welcome & welcome)
    {
        DDSMessage msg = {
            .content = { welcome }
        };

        std::vector<std::string> addedIds;
        for(const auto & addedBytes : added)
            addedIds.emplace_back(std::string{addedBytes.begin(), addedBytes.end()});

        m_network.broadcastSample(addedIds, marshalToBytes(msg));
    }

    void handleGossipDelivery(const mls::MLSMessage & message)
    {
        if(!state)
        {
            m_futureProposals.emplace_back(message);
            return;
        }

        if(message.epoch() < state->epoch())
            return; // Invalid
        else if(message.epoch() > state->epoch())
        {
            m_futureProposals.emplace_back(message);
        }
        else
            handleProposal(message);
    }

    void handleProposal(const mls::MLSMessage & message)
    {
        const auto proposalRef = state->isValidProposal(message);
        if(proposalRef)
        {
            m_deliverProposalOrMessage(message);

            m_receivedProposals.insert(proposalRef.value());

            lookUnlockCommits(proposalRef.value());
        }
        else if(state->isValidApplicationMessage(message))
            m_deliverProposalOrMessage(message);
    }

    void lookUnlockCommits(const mls::ProposalRef & newRef)
    {
        const auto commits = std::views::keys(m_incompleteCommits);

        for(const auto & commit : commits)
        {
            if(m_incompleteCommits[commit].contains(newRef))
            {
                m_incompleteCommits[commit].erase(newRef);

                if(m_incompleteCommits[commit].empty())
                {
                    m_incompleteCommits.erase(commit);
                    handleCompleteCommit(commit);
                }
            }
        }
    }

    void handleCascadeConsensusReception(const mls::MLSMessage & message)
    {
        if(!state)
        {
            m_futureCascadeConsensus.emplace_back(message);
            return;
        }

        if(message.epoch() < state->epoch())
            return; // Invalid
        else if(message.epoch() > state->epoch())
        {
            m_futureCascadeConsensus.emplace_back(message);
        }
        else
            handleCascadeConsensusMessage(message);
    }

    void handleCascadeConsensusMessage(const mls::MLSMessage & message)
    {
        const auto cascadeConsensusMessageBytes = state->isValidApplicationMessage(message);
        if(cascadeConsensusMessageBytes)
        {
            try
            {
                CascadeConsensusMessage cascadeConsensusMessage;
                mls::tls::unmarshal(cascadeConsensusMessageBytes.value(), cascadeConsensusMessage);

                m_cascadeConsensus.receiveMessage(cascadeConsensusMessage);
            }
            catch(const std::exception & e)
            {
                printf("Received incorrect Cascade Consensus message: %s\n", e.what());
            }
        }
        else
        {
            printf("Received incorrect MLS Cascade Consensus message\n");
        }
    }

    void handleCommit(const mls::MLSMessage & message)
    {
        auto referencedProposals = state->isValidCommit(message);
        if(referencedProposals)
        {
            auto referencedSet = referencedProposals.value();

            std::set<mls::ProposalRef> remainingReferences;

            std::set_difference(referencedSet.begin(), referencedSet.end(),
                m_receivedProposals.begin(), m_receivedProposals.end(),
                std::inserter(remainingReferences, remainingReferences.begin()));

            if(remainingReferences.empty())
                handleCompleteCommit(message);
            else
                m_incompleteCommits.insert({message, remainingReferences});
        }
    }

    void handleCompleteCommit(const mls::MLSMessage & message)
    {
        // TODO We might as well check that the proposal list is valid

        m_cascadeConsensus.validateCommit(message);
    }

    const mls::MLSMessage & chooseCommit(const std::vector<mls::MLSMessage> & commits)
    {
        // We choose the commit with most proposals and tie break on smallest sender id
        // TODO Investigate other use, for example to ensure a remove proposal is indeed commited
        const mls::MLSMessage * bestCommit = &commits[0];
        auto [bestSender, proposals] = state->getCommitContent(commits[0]);
        size_t bestCount = proposals.size();

        for(const auto & commit : commits)
        {
            auto [sender, proposals] = state->getCommitContent(commit);

            if(proposals.size() > bestCount
                || (proposals.size() == bestCount && bestSender.val > sender.val))
            {
                bestCommit = &commit, bestSender = sender;
                bestCount = proposals.size();
            }
        }

        return *bestCommit;
    }

    void handleConsensusDelivery(const mls::MLSMessage & message)
    {
        const auto [added, removed] = state->getCommitMembershipChanges(message);

        state = m_deliverCommit(message);
        
        if(m_proposedCommit
            && state->cipher_suite().ref(message) == state->cipher_suite().ref(m_proposedCommit.value()) && !added.empty())
        {
            sendWelcome(added, m_associatedWelcome.value());
        }

        m_gossipBcast.newEpoch(*state, removed);
        m_cascadeConsensus.newEpoch(state);

        advanceEpoch();
    }

    void advanceEpoch()
    {
        // Garbage collection
        m_receivedProposals.clear();
        m_incompleteCommits.clear();

        m_proposedCommit = {};
        m_associatedWelcome = {};

        // Unlock future proposals and future cascade consensus messages
        for(auto proposalIt = m_futureProposals.begin(); proposalIt != m_futureProposals.end(); )
        {
            if(proposalIt->epoch() == state->epoch())
            {
                handleProposal(*proposalIt);
                proposalIt = m_futureProposals.erase(proposalIt);
            }
            else if(proposalIt->epoch() < state->epoch())
                proposalIt = m_futureProposals.erase(proposalIt);
            else
                proposalIt++;
        }

        for(auto ccMessageIt = m_futureCascadeConsensus.begin();
            ccMessageIt != m_futureCascadeConsensus.end(); )
        {
            if(ccMessageIt->epoch() == state->epoch())
            {
                handleCascadeConsensusMessage(*ccMessageIt);
                ccMessageIt = m_futureCascadeConsensus.erase(ccMessageIt);
            }
            else if(ccMessageIt->epoch() < state->epoch())
                ccMessageIt = m_futureCascadeConsensus.erase(ccMessageIt);
            else
                ccMessageIt++;
        }
    }

private:
    Network & m_network;

    const welcomeCallback m_deliverWelcome;
    const messageCallback m_deliverProposalOrMessage;
    const commitCallback m_deliverCommit;
    
    GossipBcast m_gossipBcast;
    CascadeConsensus m_cascadeConsensus;

    ExtendedMLSState * state = nullptr;

    std::optional<mls::MLSMessage> m_proposedCommit = {};
    std::optional<mls::Welcome> m_associatedWelcome = {};

    std::vector<mls::MLSMessage> m_futureProposals;
    std::vector<mls::MLSMessage> m_futureCascadeConsensus;

    std::set<mls::ProposalRef> m_receivedProposals;

    struct MessageCompare // Required for std::map
    {
        bool operator()(const mls::MLSMessage & lhs, const mls::MLSMessage & rhs) const
        { return mls::tls::marshal(lhs) < mls::tls::marshal(rhs); };
    };
    std::map<mls::MLSMessage, std::set<mls::ProposalRef>, MessageCompare> m_incompleteCommits;

};

#endif
