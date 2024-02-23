/**
 * @file cascade_consensus.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Handling of the Cascade Consensus instance to deliver commits
 *  Uses the Cascade Consensus protocol from 'T. Albouy et al. Context Adaptive Cooperation'
 */

#ifndef __CASCADE_CONSENSUS_HPP__
#define __CASCADE_CONSENSUS_HPP__

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>

#include "mls/crypto.h"
#include "mls/messages.h"
#include "mls/tree_math.h"

#include "cac_broadcast.hpp"
#include "cac_signature.hpp"
#include "dds_message.hpp"
#include "extended_mls_state.hpp"
#include "full_consensus.hpp"
#include "network.hpp"
#include "restrained_consensus.hpp"

using ChoiceCallback = std::function<const mls::MLSMessage &(const std::vector<mls::MLSMessage> &)>;
using DeliverCallback = std::function<void(const mls::MLSMessage &)>;

static constexpr uint CAC_K = 1;

// To be able to reference content of CAC Message (2nd instance following RC)
template <>
const mls::bytes_ns::bytes & mls::CipherSuite::reference_label<CAC2Content>()
{
    static const auto label = from_ascii("Distributed Delivery Service 1.0 CAC 2 Content");
    return label;
}

class CascadeConsensus
{
public:
    CascadeConsensus(Network & network, int networkRtt,
        const CACBroadcast<mls::MLSMessage>::TransmitCallback & transmitCallback,
        const ChoiceCallback & choiceCallback, const DeliverCallback & deliverCallback)
        : m_network(network), m_networkRTT(networkRtt),
            m_choice(choiceCallback), m_deliver(deliverCallback),
            m_cacInstance1(CAC_K, choiceCallback, transmitCallback,
                std::bind(&CascadeConsensus::handleCAC1Delivery, this,
                    std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
                std::bind(&CascadeConsensus::broadcastCAC1Message, this, std::placeholders::_1)),
            m_cacInstance2(CAC_K,
                std::bind(&CascadeConsensus::handleCAC2Choice, this, std::placeholders::_1),
                std::bind(&CascadeConsensus::handleCAC2Candidate, this, std::placeholders::_1),
                std::bind(&CascadeConsensus::handleCAC2Delivery, this,
                    std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
                std::bind(&CascadeConsensus::broadcastCAC2Message, this, std::placeholders::_1)),
            m_restrainedConsensus(network, networkRtt,
                std::bind(&CascadeConsensus::handleRCDeliver, this,
                    std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
                std::bind(&CascadeConsensus::handleRCBottom, this),
                std::bind(&CascadeConsensus::broadcastRCMessage, this,
                    std::placeholders::_1, std::placeholders::_2)),
            m_consensus(network, networkRtt,
                std::bind(&CascadeConsensus::broadcastFullConsensusMessage,
                    this, std::placeholders::_1),
                std::bind(&CascadeConsensus::sendFullConsensusMessage, this,
                    std::placeholders::_1, std::placeholders::_2),
                std::bind(&CascadeConsensus::handleFullConsensusDelivery,
                    this, std::placeholders::_1))
    { }

    void newEpoch(ExtendedMLSState * state)
    {
        m_state = state;
        m_cacInstance1.newEpoch(state);
        m_cacInstance2.newEpoch(state);
        m_restrainedConsensus.newEpoch(state);
        m_delivered.clear();

        if(m_RCTimeout)
        {
            m_network.unregisterTimeout(m_RCTimeout.value());
            m_RCTimeout = {};
        }

        m_consensus.newEpoch(state);
        m_consensusProposed = false;
    }

    void receiveMessage(const CascadeConsensusMessage & msg)
    {
        if(msg.isCAC() || msg.isCAC2())
        {
            if(msg.instance == 1 && msg.isCAC())
            {
                m_cacInstance1.receiveMessage(msg.cacMessage());
            }
            else if(msg.instance == 2 && msg.isCAC2())
            {
                m_cacInstance2.receiveMessage(msg.cac2Message());
            }
            else
            {
                printf("Incorrect CAC Message: unexpected instance %d\n", msg.instance);
            }
        }
        else if(msg.isRestrainedConsensus())
        {
            m_restrainedConsensus.receiveMessage(msg.restrainedConsensusMessage());
        }
        else if(msg.isFullConsensus())
        {
            m_consensus.receiveMessage(msg.fullConsensusMessage());
        }
    }

    void proposeCommit(const mls::MLSMessage & commit)
    {
        m_cacInstance1.broadcast(commit);
    }

    void validateCommit(const mls::MLSMessage & commit)
    {
        m_cacInstance1.validateMessage(commit);
    }

    bool cac1HasStarted() const
    {
        return m_cacInstance1.hasStarted();
    }

protected:
    void broadcastCAC1Message(const CACMessage<mls::MLSMessage> & cacMessage)
    {
        CascadeConsensusMessage ccMessage = (CascadeConsensusMessage) {
            .instance = 1,
            .content = { cacMessage }
        };
        
        auto ccMessageBytes = marshalToBytes(ccMessage);
        DDSMessage msg = (DDSMessage) {
            .content = { m_state->protect({},
                std::vector<uint8_t>{ccMessageBytes.content, ccMessageBytes.content + ccMessageBytes.size}, 0) }
        };
        m_network.broadcast(marshalToBytes(msg));

        // Network Broadcast does not include self
        m_cacInstance1.receiveMessage(cacMessage);
    }

    void broadcastCAC2Message(const CACMessage<CAC2Content> & cacMessage)
    {
        CascadeConsensusMessage ccMessage = (CascadeConsensusMessage) {
            .instance = 2,
            .content = { cacMessage }
        };
        
        auto ccMessageBytes = marshalToBytes(ccMessage);
        DDSMessage msg = (DDSMessage) {
            .content = { m_state->protect({},
                std::vector<uint8_t>{ccMessageBytes.content, ccMessageBytes.content + ccMessageBytes.size}, 0) }
        };
        m_network.broadcast(marshalToBytes(msg));

        // Network Broadcast does not include self
        m_cacInstance2.receiveMessage(cacMessage);
    }

    void broadcastRCMessage(const RestrainedConsensusMessage & message,
        const std::vector<std::string> & recipients)
    {
        CascadeConsensusMessage ccMessage = (CascadeConsensusMessage) {
            .instance = 1,
            .content = { message }
        };
        
        auto ccMessageBytes = marshalToBytes(ccMessage);
        DDSMessage msg = (DDSMessage) {
            .content = { m_state->protect({},
                std::vector<uint8_t>{ccMessageBytes.content, ccMessageBytes.content + ccMessageBytes.size}, 0) }
        };
        m_network.broadcastSample(recipients, marshalToBytes(msg));
    }

    void broadcastFullConsensusMessage(const ConsensusMessage<CAC2Content> & message)
    {
        CascadeConsensusMessage ccMessage = (CascadeConsensusMessage) {
            .instance = 0,
            .content = { message }
        };
        
        auto ccMessageBytes = marshalToBytes(ccMessage);
        DDSMessage msg = (DDSMessage) {
            .content = { m_state->protect({},
                std::vector<uint8_t>{ccMessageBytes.content, ccMessageBytes.content + ccMessageBytes.size}, 0) }
        };
        m_network.broadcast(marshalToBytes(msg));
    }

    void sendFullConsensusMessage(const ConsensusMessage<CAC2Content> & message,
        const std::string & recipient)
    {
        CascadeConsensusMessage ccMessage = (CascadeConsensusMessage) {
            .instance = 0,
            .content = { message }
        };
        
        auto ccMessageBytes = marshalToBytes(ccMessage);
        DDSMessage msg = (DDSMessage) {
            .content = { m_state->protect({},
                std::vector<uint8_t>{ccMessageBytes.content, ccMessageBytes.content + ccMessageBytes.size}, 0) }
        };
        m_network.send(recipient, marshalToBytes(msg));
    }

    void handleCAC1Delivery(const mls::MLSMessage & message,
        const std::vector<MessageRef> & conflictSet,
        const std::vector<CACSignature> & sigs)
    {
        m_delivered.emplace_back(m_state->cipher_suite().ref(message));

        if(conflictSet.size() == 1)
        {
            m_deliver(message);
        }
        else
        {
            printf("CAC1 Deliver: Conflict between %ld commit messages\n",
                conflictSet.size());

            // Allow to test random crashes before starting a restrained consensus
            char * crashProbability = std::getenv("TEST_RC_CRASH");
            if(crashProbability && rand() % std::atoi(crashProbability) == 0)
            {
                printf("TEST_RC_CRASH: Crash\n");
                exit(0);
            }

            const auto sender = m_state->getCommitSender(message);
            if(sender == m_state->index())
            {
                std::vector<std::pair<mls::LeafIndex, MessageRef>> senderConflictSet;
                const auto messages = m_cacInstance1.messages();

                for(const auto & ref : conflictSet)
                    if(messages.contains(ref))
                        senderConflictSet.emplace_back(std::pair{
                            m_state->getCommitSender(messages.at(ref)), ref});

                m_restrainedConsensus.propose(senderConflictSet, sigs);
            }
            else if(!m_RCTimeout)
            {
                m_RCTimeout = m_network.registerTimeout(3 * m_networkRTT,
                    [this](auto){ m_RCTimeout = {}; handleRCBottom(); });
            }
        }
    }

    void handleRCDeliver(const std::vector<MessageRef> & set,
        const std::vector<mls::AuthenticatedContent> & sigs,
        const std::vector<mls::AuthenticatedContent> & retractSigs)
    {
        const auto comparator =
            [](const mls::AuthenticatedContent & lhs, const mls::AuthenticatedContent & rhs)
            { return std::get<mls::ApplicationData>(lhs.content.content).data
                < std::get<mls::ApplicationData>(rhs.content.content).data; };

        std::vector<MessageRef> sortedSet = set;
        std::vector<mls::AuthenticatedContent> sortedSigs = sigs,
            sortedRetractSigs = retractSigs;

        // Sort so that when generating the hash, a similar message will have the same hash
        //  Thus, if another member submit the same set and signature, they will be consider identical
        std::sort(sortedSet.begin(), sortedSet.end());
        std::sort(sortedSigs.begin(), sortedSigs.end(), comparator);
        std::sort(sortedRetractSigs.begin(), sortedRetractSigs.end(),
            comparator);

        sortedSigs.insert(sortedSigs.end(), sortedRetractSigs.begin(),
            sortedRetractSigs.end());

        m_cacInstance2.broadcast((CAC2Content) {
            .conflictingMessages = sortedSet,
            .signatures = sortedSigs
        });
    }

    void handleRCBottom()
    {
        const auto comparator =
            [](const mls::AuthenticatedContent & lhs, const mls::AuthenticatedContent & rhs)
            { return std::get<mls::ApplicationData>(lhs.content.content).data
                < std::get<mls::ApplicationData>(rhs.content.content).data; };

        std::sort(m_delivered.begin(), m_delivered.end());

        std::vector<mls::AuthenticatedContent> sigs;
        for(const auto & sig : m_cacInstance1.signatures())
        {
            sigs.emplace_back(sig.second.authContent);
        }
        std::sort(sigs.begin(), sigs.end(), comparator);

        m_cacInstance2.broadcast((CAC2Content) {
            .conflictingMessages = m_delivered,
            .signatures = sigs
        });
    }

    void handleCAC2Delivery(const CAC2Content & message,
        const std::vector<MessageRef> & conflictSet,
        const std::vector<CACSignature> & sigs)
    {
        (void) sigs;

        if(m_RCTimeout)
        {
            m_network.unregisterTimeout(m_RCTimeout.value());
            m_RCTimeout = {};
        }

        if(conflictSet.size() == 1)
        {
            printf("CAC2 Deliver: Agreement reached on a set of %ld messages\n",
                message.conflictingMessages.size());

            std::vector<mls::MLSMessage> choices;
            for(const auto & ref : message.conflictingMessages)
            {
                if(!m_cacInstance1.messages().contains(ref))
                    printf("CAC2 Deliver: Error unknown reference %u\n",
                        MLS_UTIL_HASH_REF(ref));
                else
                    choices.emplace_back(m_cacInstance1.messages().at(ref));
            }

            m_deliver(m_choice(choices));
        }
        else if(!m_consensusProposed)
        {
            m_consensusProposed = true;

            printf("CAC2 Deliver: Conflict between %ld messages\n",
                conflictSet.size());

            m_consensus.propose(message);
        }
    }

    void handleCAC2Candidate(const CAC2Content & content)
    {
        // TODO Something better (e.g. don't validate if signatures not valid)

        m_cacInstance2.validateMessage(content);
    }

    const CAC2Content & handleCAC2Choice(const std::vector<CAC2Content> & choices)
    {
        // Choice is not important as multiple possibilities will lead to Full Consensus
        return choices[0];
    }

    void handleFullConsensusDelivery(const CAC2Content & decidedContent)
    {
        printf("Full Consensus: Agreement reached\n");

        std::vector<mls::MLSMessage> choices;
        for(const auto & ref : decidedContent.conflictingMessages)
        {
            if(!m_cacInstance1.messages().contains(ref))
                printf("CAC2 Deliver: Error unknown reference %u\n",
                    MLS_UTIL_HASH_REF(ref));
            else
                choices.emplace_back(m_cacInstance1.messages().at(ref));
        }

        m_deliver(m_choice(choices));
    }

private:
    Network & m_network;
    const int m_networkRTT;
    ExtendedMLSState * m_state = nullptr;

    const ChoiceCallback m_choice;
    const DeliverCallback m_deliver;

    CACBroadcast<mls::MLSMessage> m_cacInstance1;
    CACBroadcast<CAC2Content> m_cacInstance2;

    std::vector<MessageRef> m_delivered;

    RestrainedConsensus m_restrainedConsensus;
    std::optional<timeoutID> m_RCTimeout = {};

    FullConsensus<CAC2Content> m_consensus;
    bool m_consensusProposed;
};

#endif
