/**
 * @file restrained_consensus.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Implementation of Cascade Consensus's Restrained Consensus for
 *  Distributed Delivery Service
 */

#ifndef __RESTRAINED_CONSENSUS_HPP__
#define __RESTRAINED_CONSENSUS_HPP__

#include <algorithm>
#include <bits/chrono.h>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "bytes/bytes.h"
#include "mls/messages.h"
#include "mls/tree_math.h"
#include "tls/tls_syntax.h"

#include "cac_signature.hpp"
#include "dds_message.hpp"
#include "extended_mls_state.hpp"
#include "network.hpp"

class RestrainedConsensus
{
public:
    using DecideCallback = std::function<void(const std::vector<MessageRef> &,
        const std::vector<mls::AuthenticatedContent> &,
        const std::vector<mls::AuthenticatedContent> &)>;
    using BottomCallback = std::function<void()>;
    using BroadcastCallback = std::function<void(const RestrainedConsensusMessage &,
        const std::vector<std::string> &)>;

    RestrainedConsensus(Network & network, int networkRtt,
        const DecideCallback & decideCallback, const BottomCallback & bottomCallback,
        const BroadcastCallback & broadcastCallback)
        : m_network(network), m_networkRtt(networkRtt), m_decide(decideCallback),
            m_bottom(bottomCallback), m_broadcast(broadcastCallback)
    { }

    void newEpoch(ExtendedMLSState * state)
    {
        m_state = state;

        m_retract = false, m_hasDelivered = false, m_hasFinished = false;
        m_powerSet.clear(), m_signed.clear(), m_retracted.clear();

        resetTimeout();
    }

    void propose(const std::vector<std::pair<mls::LeafIndex, MessageRef>> & conflictSet,
        const std::vector<CACSignature> & sigs)
    {
        if(!m_retract && !m_hasDelivered)
        {
            m_hasDelivered = true;

            std::vector<mls::AuthenticatedContent> sigSet;

            m_powerSet = powerSet(conflictSet);
            for(const auto & elt : m_powerSet)
                if(std::any_of(elt.begin(), elt.end(),
                    [this](const auto & pair)
                    { return pair.first == m_state->index(); }))
                {
                    const auto sig = m_state->sign(
                        mls::tls::marshal(elt));
                    sigSet.emplace_back(sig);

                    m_signed[{elt.begin(), elt.end()}][m_state->index()] = sig;
                }

            for(const auto & retract : m_retracted)
            {
                const auto retracted = std::get<mls::MemberSender>(
                        retract.content.sender.sender).sender;
                handleRetract(retracted);
            }

            std::vector<mls::AuthenticatedContent> proofs;
            std::transform(sigs.begin(), sigs.end(),
                std::back_inserter(proofs),
                [](const auto & sig){ return sig.authContent; });
            RestrainedConsContent content = {
                .sigSet = sigSet,
                .powerConflictSet = m_powerSet,
                .proofs = proofs
            };

            // Allow to test delay before sending restrained cons (otherwise with no delay everybody else immediately RETRACT)
            char * delay = std::getenv("TEST_RC_DELAY");
            if(delay)
            {
                std::vector<std::pair<mls::LeafIndex, MessageRef>> copy{conflictSet};
                int delayValue = atoi(delay);

                std::thread{[delayValue, content, copy, this]()
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(delayValue));

                    m_broadcast(RestrainedConsensusMessage{content},
                        getParticipants(copy));
                }}.detach();
            }
            else
            {
                m_broadcast(RestrainedConsensusMessage{content},
                    getParticipants(conflictSet));
            }

            m_timeout = m_network.registerTimeout(2 * m_networkRtt,
                [this](auto){ m_timeout = {}; bottom(); });
        }   
    }

    void receiveMessage(const RestrainedConsensusMessage & message)
    {
        if(m_hasFinished)
            return;

        if(message.isRestrainedCons())
        {
            handleRestrainedCons(message.restrainedCons());
        }
        else if(message.isRetract())
        {
            handleRetract(message.retract());
        }
    }

protected:
    void handleRestrainedCons(const RestrainedConsContent & content)
    {
        // Check "foreign-proofs is invalid"
        std::vector<CACSignature> proofs;
        for(const auto & sig : content.proofs)
        {
            auto cacSig = CACSignature::verifyAndConvert(*m_state, sig);
            if(!cacSig)
            {
                bottom();
                return;
            }
            else
                proofs.emplace_back(cacSig.value());
        }

        // Then we need to check the correct sequencing of messages (check there's no gap)
        std::map<mls::LeafIndex, std::set<uint32_t>> sequences;
        for(const auto & sig : proofs)
            sequences[sig.sender()].insert(sig.sequence);
        for(const auto & [_, seq] : sequences)
            if(*seq.rbegin() > seq.size() - 1)
            {
                bottom();
                return;
            }

        // Who sent the restrained-cons ?
        if(content.sigSet.empty()
            || content.sigSet[0].content.sender.sender_type() != mls::SenderType::member)
        {
            bottom();
            return;
        }
        const mls::LeafIndex sender = std::get<mls::MemberSender>(
            content.sigSet[0].content.sender.sender).sender;

        // Check "a signature in sigset is invalid"
        std::map<std::set<std::pair<mls::LeafIndex, MessageRef>>,
            mls::AuthenticatedContent> signedSet;
        for(const auto & sig : content.sigSet)
        {
            if(!m_state->verify(sig)
                || sig.content.sender.sender_type() != mls::SenderType::member
                || std::get<mls::MemberSender>(
                    content.sigSet[0].content.sender.sender).sender != sender)
            {
                bottom();
                return;
            }

            try
            {
                std::vector<std::pair<mls::LeafIndex, MessageRef>> signedContent;
                mls::tls::unmarshal(
                    std::get<mls::ApplicationData>(sig.content.content).data,
                    signedContent);

                signedSet[{signedContent.begin(), signedContent.end()}] = sig;
            }
            catch(const std::exception &)
            {
                bottom();
                return;
            }
        }

        // TODO Other verifications

        if(m_hasDelivered)
        {
            for(const auto & [signedElt, sig] : signedSet)
                m_signed[signedElt][sender] = sig;

            checkCompletion();
        }
        else
        {
            const auto & sig = m_state->sign(mls::bytes_ns::from_ascii("RETRACT"));

            m_retract = true;
            m_broadcast(RestrainedConsensusMessage{ sig }, getParticipants(content.powerConflictSet));

            // TODO Why timeout, if I retract I will never decide but other can still decide
            // if(!m_timeout)
            //     m_timeout = m_network.registerTimeout(2 * m_networkRtt,
            //         [this](auto){ m_timeout = {}; bottom(); });
        }
    }

    void handleRetract(const mls::AuthenticatedContent & retract)
    {
        if(retract.content.sender.sender_type() != mls::SenderType::member)
            return; // Invalid sender;

        if(retract.content.epoch != m_state->epoch())
            return; // Replay message attack

        if(!m_state->verify(retract))
            return; // Invalid

        if(std::any_of(m_retracted.begin(), m_retracted.end(),
            [&retract](const auto & retracted){ return retracted.content.sender == retract.content.sender; }))
            return; // Already retracted

        m_retracted.emplace_back(retract);
        const auto retracted = std::get<mls::MemberSender>(retract.content.sender.sender).sender;

        handleRetract(retracted);

        checkCompletion();
    }

    void handleRetract(const mls::LeafIndex & retracted)
    {
        m_powerSet.erase(std::remove_if(m_powerSet.begin(), m_powerSet.end(),
            [retracted](const auto & elt)
            {
                return std::any_of(elt.begin(), elt.end(),
                    [retracted](const auto & pair){ return pair.first == retracted; });
            }), m_powerSet.end());
    }

    void checkCompletion()
    {
        if(m_powerSet.empty())
            return;

        // Look for biggest element in powerSet
        std::vector<std::pair<mls::LeafIndex, MessageRef>> biggest = m_powerSet[0];
        bool uniqueBiggest = true;
        for(auto it = std::next(m_powerSet.begin()); it != m_powerSet.end(); ++it)
        {
            if(it->size() > biggest.size())
            {
                biggest = *it;
                uniqueBiggest = true;
            }
            else if(it->size() == biggest.size())
                uniqueBiggest = false;
        }

        if(!uniqueBiggest)
        {
            bottom();
            return;
        }
        else
        {
            const auto biggestSigs = m_signed[{biggest.begin(), biggest.end()}];

            if(biggestSigs.size() == biggest.size())
            {
                m_hasFinished = true;
                resetTimeout();

                std::vector<MessageRef> messages;
                std::transform(biggest.begin(), biggest.end(),
                    std::back_inserter(messages),
                    [](const auto & pair){ return pair.second; });

                std::vector<mls::AuthenticatedContent> sigs;
                std::transform(biggestSigs.begin(), biggestSigs.end(),
                    std::back_inserter(sigs),
                    [](const auto & pair){ return pair.second; });

                m_decide(messages, sigs, m_retracted);
            }
        }
    }

    void bottom()
    {
        if(m_hasFinished)
            return;

        m_hasFinished = true;

        resetTimeout();
        m_bottom();
    }

    void resetTimeout()
    {
        if(m_timeout)
        {
            m_network.unregisterTimeout(m_timeout.value());
            m_timeout = {};
        }
    }

    std::vector<std::string> getParticipants(
        const std::vector<std::pair<mls::LeafIndex, MessageRef>> & conflictSet)
    {
        std::vector<std::string> participants;

        for(const auto & [index, _] : conflictSet)
        {
            const auto & name = m_state->getMemberNameByIndex(index);

            participants.emplace_back(std::string{name.data(), name.data() + name.size()});
        }

        return participants;
    }

    std::vector<std::string> getParticipants(
        const std::vector<std::vector<std::pair<mls::LeafIndex, MessageRef>>> & powerSet)
    {
        std::vector<std::string> participants;

        for(const auto & elt : powerSet)
        {
            if(elt.size() != 1)
                continue; // Optimize time (there will be an elt of size 1 for each sender)

            const auto & [index, _] = elt[0];
            const auto & name = m_state->getMemberNameByIndex(index);
            participants.emplace_back(std::string{name.data(), name.data() + name.size()});
        }

        return participants;
    }

    template <typename T>
    std::vector<std::vector<T>> powerSet(const std::vector<T>& input, size_t index = 0)
    {
        if(index == input.size())
        {
            return {{}};
        }

        std::vector<std::vector<T>> subsets = powerSet(input, index + 1);

        size_t subsetCount = subsets.size();
        for(size_t i = 0; i < subsetCount; ++i)
        {
            std::vector<T> currentSubset = subsets[i];
            currentSubset.push_back(input[index]);
            subsets.push_back(currentSubset);
        }

        return subsets;
    }

private:
    Network & m_network;
    const int m_networkRtt;

    ExtendedMLSState * m_state = nullptr;

    const DecideCallback m_decide;
    const BottomCallback m_bottom;
    const BroadcastCallback m_broadcast;

    bool m_retract, m_hasDelivered, m_hasFinished;
    std::vector<std::vector<std::pair<mls::LeafIndex, MessageRef>>> m_powerSet;
    std::map<
        std::set<std::pair<mls::LeafIndex, MessageRef>>,
        std::map<mls::LeafIndex, mls::AuthenticatedContent>> m_signed;
    std::vector<mls::AuthenticatedContent> m_retracted;

    std::optional<timeoutID> m_timeout = {};
};

#endif
