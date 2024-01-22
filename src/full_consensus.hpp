/**
 * @file full_consensus.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Simplified implementation of PBFT from
 *  'M. Castro et al. Practical Byzantine Fault Tolerance' to complete the
 *  Cascade Consensus protocol
 *
 *  Simplification: no checkpoints, no sequence, consensus instance allow to
 *      decide on one commit and is then reset
 *  TODO: To optimize bandwidth, the actual message is not sent during
 *      every phase, but referred to using a hash most of the time. It is
 *      possible to reach a decision to deliver this message without having
 *      received this message before (i.e. I received 2f + 1 commit for
 *      this message but the probably malicious leader never sent me the
 *      associated pre-prepare message). Therefore, we should introduce
 *      a mechanism to allow a given member to ask other members for this
 *      message. This mechanism could be similar to the one that would allow
 *      disconnected group members to synchronize with the group after being
 *      offline for a certain period of time.
 */

#ifndef __FULL_CONSENSUS_HPP__
#define __FULL_CONSENSUS_HPP__

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <queue>
#include <set>
#include <vector>

#include "mls/messages.h"
#include "mls/tree_math.h"
#include "tls/tls_syntax.h"

#include "dds_message.hpp"
#include "extended_mls_state.hpp"
#include "network.hpp"

template <typename T>
class FullConsensus
{
public:
    using BroadcastCallback = std::function<void(const ConsensusMessage<T> &)>;
    using SendCallback = std::function<void(const ConsensusMessage<T> &, const std::string &)>;
    using DeliverCallback = std::function<void(const T &)>;

    FullConsensus(Network & network, uint networkRtt,
        const BroadcastCallback & broadcastCallback,
        const SendCallback & sendCallback, const DeliverCallback & deliverCallback)
        : m_network(network), m_networkRTT(networkRtt), m_broadcast(broadcastCallback),
            m_send(sendCallback), m_deliver(deliverCallback)
    { }

    void newEpoch(ExtendedMLSState * state)
    {
        m_state = state;

        const uint n = m_state->getMembersIdentity(false).size(); // TODO Not very efficient
        f = (n - 1) / 3;

        m_futureMessages.clear();
        m_messages.clear(); // We assume it won't get too big so no need to clear between views

        m_proposedMessage = {};
        newView(0);
    }

    void propose(const T & proposedMessage)
    {
        if(m_proposedMessage)
            return;

        m_proposedMessage = { proposedMessage };
        if(!m_hasSentPrepare)
            proposeCurrentValue();
    }

    void receiveMessage(const ConsensusMessage<T> & message)
    {
        if(message.type() == ConsensusMessageType::CONSENSUS_PROPOSE)
        {
            const auto & propose = message.proposeMessage();

            if(propose.view == m_currentView)
                handlePropose(propose.content);
            else if(propose.view > m_currentView)
                m_futureMessages[propose.view].push(message);
        }
        else if(message.type() == ConsensusMessageType::CONSENSUS_PRE_PREPARE)
        {
            const auto prePrepare = message.prePrepareMessage();
            const auto content = getContentIfReady(prePrepare.signedContent,
                message);

            if(content)
                handlePrePrepare(content->first, content->second,
                    prePrepare.proposedMessage);
        }
        else if(message.type() == ConsensusMessageType::CONSENSUS_PREPARE)
        {
            const auto prepare = message.prepareMessage();
            const auto content = getContentIfReady(prepare.signedContent,
                message);

            if(content)
                handlePrepare(content->first, content->second);
        }
        else if(message.type() == ConsensusMessageType::CONSENSUS_COMMIT)
        {
            const auto commit = message.commitMessage();
            const auto content = getContentIfReady(commit.signedContent,
                message);

            if(content)
                handleCommit(content->first, content->second);
        }
        else if(message.type() == ConsensusMessageType::CONSENSUS_VIEW_CHANGE)
        {
            const auto viewChange = message.viewChange();
            
            if(viewChange.content.sender.sender_type() != mls::SenderType::member)
                return;

            const auto sender = std::get<mls::MemberSender>(
                viewChange.content.sender.sender).sender;

            const auto content = m_state->verifyAndExtract<ViewChangeMessageContent>(viewChange);
            if(content)
            {
                if(content->view == m_currentView + 1)
                    handleViewChange(sender, content->view);
                else if(content->view > m_currentView)
                    m_futureMessages[content->view].push(message);
            }
        }
    }

protected:
    void newView(uint32_t view)
    {
        m_currentView = view;

        // Determine new leader deterministically (using epoch number to change leader periodically)
        auto members = m_state->getMembersIndexes();
        std::sort(members.begin(), members.end());
        const uint leader = (view + m_state->epoch()) % members.size();
        m_currentLeaderIdx = members[leader];
        const auto name = m_state->getMemberNameByIndex(m_currentLeaderIdx);
        m_currentLeader = std::string{name.data(), name.data() + name.size()};

        m_prePreparedMessage = {};
        m_hasSentPrePrepare = false, m_hasSentPrepare = false, m_hasSentCommit = false;
        m_signedPrepare.clear(), m_signedCommit.clear();
        m_signedNewView.clear();

        resetTimers();

        while(!m_futureMessages[view].empty())
        {
            auto message = m_futureMessages[view].front();
            m_futureMessages[view].pop();
            receiveMessage(message);
        }

        if(m_proposedMessage && !m_hasSentPrepare && !m_hasSentPrePrepare)
            proposeCurrentValue();
    }

    void proposeCurrentValue()
    {
        if(m_currentLeaderIdx == m_state->index())
        {
            handlePropose(m_proposedMessage.value());
        }
        else
        {
            ConsensusMessage<T> message = {
                .content = (ConsensusProposeMessage<T>) {
                    .view = m_currentView,
                    .content = m_proposedMessage.value()
                }
            };
            m_send(message, m_currentLeader);

            m_timeout = m_network.registerTimeout(m_networkRTT,
                [this](auto){ m_timeout = {}, handleProposeTimeout(); });
        }
    }

    void handleProposeTimeout()
    {
        ConsensusMessage<T> message = {
            .content = (ConsensusProposeMessage<T>) {
                .view = m_currentView,
                .content = m_prePreparedMessage
                    ? m_prePreparedMessage.value() : m_proposedMessage.value()
            }
        };
        m_broadcast(message);

        m_forwardTimeout = m_network.registerTimeout(m_networkRTT,
            [this](auto){ m_forwardTimeout = {}; handleForwardTimeout(); });
    }

    void handleForwardTimeout()
    {
        ConsensusMessage<T> message = {
            .content = m_state->sign(mls::tls::marshal((ViewChangeMessageContent) {
                .view = m_currentView + 1
            }))
        };
        m_broadcast(message);
    }

    void handlePropose(const T & proposed)
    {
        m_messages[m_state->cipher_suite().ref(proposed)] = proposed;

        if(m_currentLeaderIdx == m_state->index() && !m_hasSentPrePrepare)
        {
            m_hasSentPrePrepare = true;

            ConsensusMessage<T> message = {
                .content = (ConsensusPrePrepareMessage<T>) {
                    .signedContent = m_state->sign(mls::tls::marshal((ConsensusMessageContent) {
                        .view = m_currentView,
                        .consensusMessage = m_state->cipher_suite().ref(proposed)
                    })),
                    .proposedMessage = proposed
                }
            };
            m_broadcast(message);
        }
        else
        {
            ConsensusMessage<T> message = {
                .content = (ConsensusProposeMessage<T>) {
                    .view = m_currentView,
                    .content = proposed
                }
            };
            m_send(message, m_currentLeader);

            m_forwardTimeout = m_network.registerTimeout(m_networkRTT,
            [this](auto){ m_forwardTimeout = {}; handleForwardTimeout(); });
        }
    }

    void handlePrePrepare(const mls::LeafIndex & sender,
        const ConsensusMessageContent & content, const T & proposed)
    {
        if(m_currentLeaderIdx == m_state->index()
            || sender != m_currentLeaderIdx)
            return;

        m_messages[m_state->cipher_suite().ref(proposed)] = proposed;
        resetTimers();

        if(!m_hasSentPrepare)
        {
            m_hasSentPrepare = true;
            m_proposedMessage = proposed;

            m_timeout = m_network.registerTimeout(m_networkRTT, [this](auto)
            { m_timeout = {}; handleProposeTimeout(); });

            ConsensusMessage<T> message = {
                .content = (ConsensusPrepareMessage) {
                    .signedContent = m_state->sign(mls::tls::marshal((ConsensusMessageContent) {
                        .view = m_currentView,
                        .consensusMessage = content.consensusMessage
                    }))
                }
            };
            m_broadcast(message);
        }
    }

    void handlePrepare(const mls::LeafIndex & sender,
        const ConsensusMessageContent & content)
    {
        m_signedPrepare[content.consensusMessage].insert(sender);

        if(m_signedPrepare[content.consensusMessage].size() >= 2*f + 1
            && !m_hasSentCommit)
        {
            m_hasSentCommit = true;
            resetTimers();

            ConsensusMessage<T> message = {
                .content = (ConsensusCommitMessage) {
                    .signedContent = m_state->sign(mls::tls::marshal((ConsensusMessageContent) {
                        .view = m_currentView,
                        .consensusMessage = content.consensusMessage
                    }))
                }
            };
            m_broadcast(message);
        }
    }

    void handleCommit(const mls::LeafIndex & sender,
        const ConsensusMessageContent & content)
    {
        m_signedCommit[content.consensusMessage].insert(sender);

        if(m_signedCommit[content.consensusMessage].size() >= 2*f + 1)
            m_deliver(m_messages[content.consensusMessage]);
    }

    void handleViewChange(const mls::LeafIndex & sender,
        uint32_t view)
    {
        m_signedNewView.insert(sender);

        if(m_signedNewView.size() >= 2*f + 1)
            newView(view);
    }

    void resetTimers()
    {
        if(m_timeout)
        {
            m_network.unregisterTimeout(m_timeout.value());
            m_timeout = {};
        }
        if(m_forwardTimeout)
        {
            m_network.unregisterTimeout(m_forwardTimeout.value());
            m_forwardTimeout = {};
        }
    }

    std::optional<std::pair<mls::LeafIndex, ConsensusMessageContent>>
    getContentIfReady(const mls::AuthenticatedContent & authContent,
        const ConsensusMessage<T> & message)
    {
        if(authContent.content.sender.sender_type() != mls::SenderType::member)
            return {};

        auto sender = std::get<mls::MemberSender>(
            authContent.content.sender.sender).sender;

        auto content = m_state->verifyAndExtract<ConsensusMessageContent>(authContent);
        if(content)
        {
            if(content->view == m_currentView)
                return {{sender, content.value()}};
            else if(content->view > m_currentView)
                m_futureMessages[content->view].push(message);
        }

        return {};
    }

private:
    Network & m_network;
    const int m_networkRTT;
    ExtendedMLSState * m_state = nullptr;

    const BroadcastCallback m_broadcast;
    const SendCallback m_send;
    const DeliverCallback m_deliver;

    uint32_t m_currentView;
    std::string m_currentLeader;
    mls::LeafIndex m_currentLeaderIdx;
    uint f;

    std::map<uint32_t, std::queue<ConsensusMessage<T>>> m_futureMessages;
    bool m_hasSentPrePrepare, m_hasSentPrepare, m_hasSentCommit;
    std::map<MessageRef, std::set<mls::LeafIndex>> m_signedPrepare, m_signedCommit;
    std::set<mls::LeafIndex> m_signedNewView;
    std::map<MessageRef, T> m_messages;

    std::optional<T> m_proposedMessage = {}, m_prePreparedMessage = {};
    std::optional<timeoutID> m_timeout = {}, m_forwardTimeout = {};

};

#endif
