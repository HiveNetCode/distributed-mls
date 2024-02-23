/**
 * @file cac_broadcast.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Implementation of Cascade Consensus's CAC Broadcast for Distributed
 *  Delivery Service
 *
 *  TODO: To optimize bandwidth, the actual message is not sent during
 *      every phase, but referred to using a hash most of the time. It is possible
 *      to reach a decision to deliver a message without having received this
 *      message before. If the diffusion of this message is not guaranteed,
 *      we should introduce a mechanism to allow a given member to ask other
 *      members for this message. This mechanism could be similar to the one
 *      that would allow disconnected group members to synchronize with the
 *      group after being offline for a certain period of time.
 */

#ifndef __CAC_BROADCAST_HPP__
#define __CAC_BROADCAST_HPP__

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <map>
#include <optional>
#include <queue>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

#include "mls/messages.h"
#include "mls/tree_math.h"

#include "cac_signature.hpp"
#include "dds_message.hpp"
#include "extended_mls_state.hpp"

// The only assumption made on type MessageT is that the message can be hashed
//  using ExtendedMLSState::cipher_suite().ref()
// Additionally the type MessageT should fit into the encoding of a CACMessage
template <typename MessageT>
class CACBroadcast
{
public:
    using ChoiceCallback = std::function<const MessageT &(const std::vector<MessageT> &)>;
    using TransmitCallback = std::function<void(const MessageT &)>;
    using CACDeliverCallback = std::function<void(const MessageT &,
        const std::vector<MessageRef> &, const std::vector<CACSignature> &)>;
    using CACBroadcastCallback = std::function<void(const CACMessage<MessageT> &)>;

    CACBroadcast(uint k, const ChoiceCallback & choiceCallback,
        const TransmitCallback & transmitCallback,
        const CACDeliverCallback & cacDeliverCallback,
        const CACBroadcastCallback & cacBroadcastCallback)
        : k(k), m_choice(choiceCallback), m_transmit(transmitCallback),
            m_deliver(cacDeliverCallback), m_broadcast(cacBroadcastCallback)
    { }

    void newEpoch(ExtendedMLSState * state)
    {
        m_state = state;

        assert(k >= 1);
        n = m_state->getMembersIdentity(false).size(); // TODO Not very efficient
        t = (n - k) / 5; // TODO Consider case n>3t+k and n>5t+k
        qw = 4*t + k; // TODO Not sure 4t for n>5t+k
        qr = n - t; 

        m_sigCount = 0;
        m_hasSentReady = false;

        m_messages.clear();
        m_validSignatures.clear();
        m_validMessages.clear(), m_seenMessages.clear(), m_waitingMessages.clear(),
            m_deliveredMessages.clear();
        m_sequences.clear();
        m_signaturesCount.clear();

        m_waitingMessages.clear();
    }

    // Return whether the broadcast instance has started for the current epoch
    bool hasStarted() const
    {
        return m_sigCount > 0;
    }

    void broadcast(const MessageT & message)
    {
        if(m_sigCount > 0) // Already signed a statement
            return;

        const MessageRef ref = m_state->cipher_suite().ref(message);

        m_messages.insert({ref, message});
        m_seenMessages.insert(ref);
        m_validMessages.insert(ref);

        emitSignature(CACSignature::WITNESS, ref);
        
        broadcastMessage(CACSignature::WITNESS, { message });
    }

    void receiveMessage(const CACMessage<MessageT> & message)
    {
        // Serialize handling of messages (avoid recursive calls to CAC Broadcast)
        m_messageQueue.push(message);

        if(!m_messageQueueLock)
        {
            m_messageQueueLock = true;

            while(!m_messageQueue.empty())
            {
                const auto msg = m_messageQueue.front();
                m_messageQueue.pop();

                _receiveMessage(msg);
            }

            m_messageQueueLock = false;
        }
    }

    void _receiveMessage(const CACMessage<MessageT> & message)
    {
        if(message.hasBroadcastMessage())
        {
            const MessageRef ref = m_state->cipher_suite().ref(message.broadcastMessage());
            if(!m_messages.contains(ref))
                m_messages[ref] = message.broadcastMessage();
        }

        std::set<CACSignature> outOfOrderSigs; // Sigs might not be stored by order of their sequence number
        for(const auto & sig : message.sigs)
        {
            if(m_validSignatures.contains(m_state->cipher_suite().ref(sig)))
                continue;

            const auto verifiedSig = CACSignature::verifyAndConvert(*m_state, sig);
            if(verifiedSig)
            {
                // printf("New verified signature %s\n", verifiedSig->toString().c_str());

                if(verifiedSig->sequence > m_sequences[verifiedSig->sender()] + 1)
                    outOfOrderSigs.insert(verifiedSig.value());
                else
                    processNewSig(verifiedSig.value()); // Will increase the sequence
            }
        }

        std::set<CACSignature> processedSignatures;
        do // Loop through out of order signatures to check them (TODO: improve)
        {
            for(const auto & sig : processedSignatures)
                outOfOrderSigs.erase(sig);
            processedSignatures.clear();

            for(const auto & sig : outOfOrderSigs)
            {
                if(sig.sequence <= m_sequences[sig.sender()] + 1)
                {
                    processNewSig(sig);
                    processedSignatures.insert(sig);
                }
            }
        }
        while(!processedSignatures.empty());

        if(message.isWitness())
            receivedWitness();
        else if(message.isReady())
            receivedReady();
    }

    void validateMessage(const MessageT & message)
    {
        const MessageRef ref = m_state->cipher_suite().ref(message);
        m_validMessages.insert(ref);

        if(m_sigCount == 0) // Has not sign any statement yet
        {
            std::vector<MessageT> choices;
            for(const auto & validRef : m_validMessages)
                choices.emplace_back(m_messages[validRef]);
            const MessageT & chosen = m_choice(choices);

            const MessageRef chosenRef = m_state->cipher_suite().ref(chosen);
            m_waitingMessages.erase(chosenRef);

            emitSignature(CACSignature::WITNESS, chosenRef);

            // TODO Think about not piggybacking the message
            broadcastMessage(CACSignature::WITNESS, { chosen });
        }

        if(m_waitingMessages.contains(ref))
        {
            m_waitingMessages.erase(ref);

            emitSignature(CACSignature::WITNESS, ref);
            broadcastMessage(CACSignature::WITNESS);
        }
    }

    const std::map<MessageRef, MessageT> & messages() const
    {
        return m_messages;
    }

    const std::map<AuthContentRef, CACSignature> & signatures() const
    {
        return m_validSignatures;
    }

protected:
    void receivedWitness()
    {
        std::vector<MessageRef> toBeTransmitted;
        for(const auto & [ref, _] : m_signaturesCount)
        {
            if(!m_seenMessages.contains(ref)
                && m_messages.contains(ref))
            {
                m_seenMessages.insert(ref);
                toBeTransmitted.emplace_back(ref);
            }
        }
        for(const auto & ref : toBeTransmitted) // Outside of iteration to avoid race condition
        {
            m_transmit(m_messages[ref]);
        }

        if(m_sigCount == 0 && m_validMessages.size()) // Has not sign any statement yet
        {
            std::vector<MessageT> choices;
            for(const auto & validRef : m_validMessages)
                choices.emplace_back(m_messages[validRef]);
            const MessageT & chosen = m_choice(choices);

            const MessageRef chosenRef = m_state->cipher_suite().ref(chosen);
            emitSignature(CACSignature::WITNESS, chosenRef);

            // TODO Think about not piggybacking the message
            broadcastMessage(CACSignature::WITNESS, { chosen });
        }

        if(std::any_of(m_signaturesCount.begin(), m_signaturesCount.end(),
            [this](const auto & sigs)
            { return sigs.second.witnessCount() >= (n + t) / 2 + 1; }))
        {
            for(const auto & message : messagesWithEnoughWitness())
            {
                if(!m_signaturesCount[message].signedReady.contains(m_state->index()))
                {
                    emitSignature(CACSignature::READY, message);
                    broadcastMessage(CACSignature::READY);
                }

                if(n > 5*t && m_signaturesCount[message].witnessCount() >= n - t
                    && m_signaturesCount.size() == 1 // forall m' != m, witCount(m') = 0
                    && !m_deliveredMessages.contains(message))
                {
                    m_deliver(m_messages[message], { message }, validSignatures());
                }
            }
        }

        const size_t seenProcesses = m_sequences.size() + 1;
        if(seenProcesses >= n - t && !m_hasSentReady)
        {
            const auto msgWithEnoughWitness = std::find_if(
                m_signaturesCount.begin(), m_signaturesCount.end(),
                [this, seenProcesses](const auto & sigs)
                { return sigs.second.witnessCount() >= seenProcesses - 2*t; });

            if(n > 5*t && msgWithEnoughWitness != m_signaturesCount.end()
                && !m_signaturesCount[msgWithEnoughWitness->first]
                    .signedWitness.contains(m_state->index())
                && m_validMessages.contains(msgWithEnoughWitness->first))
            {
                emitSignature(CACSignature::WITNESS, msgWithEnoughWitness->first);

                broadcastMessage(CACSignature::WITNESS);
            }
            else
            {
                std::map<MessageRef, MessageSigs> witnessedMessages;
                std::copy_if(m_signaturesCount.begin(), m_signaturesCount.end(),
                    std::inserter(witnessedMessages, witnessedMessages.begin()),
                    [](const auto & sigs){ return sigs.second.witnessCount() > 0; });

                const size_t minWitnesses = std::max<int>(1, n - t * (witnessedMessages.size() + 1));
                for(const auto & msg : witnessedMessages)
                {
                    if(msg.second.witnessCount() >= minWitnesses
                        && !m_waitingMessages.contains(msg.first)
                        && !m_signaturesCount[msg.first].signedWitness
                            .contains(m_state->index()))
                    {
                        if(m_validMessages.contains(msg.first))
                        {
                            emitSignature(CACSignature::WITNESS, msg.first);

                            broadcastMessage(CACSignature::WITNESS);
                        }
                        else
                            m_waitingMessages.insert(msg.first);
                    }
                }
            }
        }
    }

    void receivedReady()
    {
        const auto readyMessages = messagesWithEnoughWitness();

        if(!readyMessages.empty())
        {
            for(const auto & readyMsg : readyMessages)
                if(!m_signaturesCount[readyMsg].signedReady.contains(m_state->index()))
                {
                    emitSignature(CACSignature::READY, readyMsg);
                    broadcastMessage(CACSignature::READY);
                }

            std::vector<MessageRef> conflictSet;
            for(const auto & messageSigs : m_signaturesCount)
                if(messageSigs.second.witnessCount() >= k)
                    conflictSet.emplace_back(messageSigs.first);

            for(const auto & ref : conflictSet)
                if(m_signaturesCount[ref].readyCount() >= qr
                    && !m_deliveredMessages.contains(ref))
                {
                    m_deliveredMessages.insert(ref);

                    m_deliver(m_messages[ref], conflictSet, validSignatures());
                }
        }
    }

    // Message that received more than qW witness signatures
    std::vector<MessageRef> messagesWithEnoughWitness()
    {
        std::vector<MessageRef> readyMessages;
        for(const auto & messageSigs : m_signaturesCount)
            if(messageSigs.second.witnessCount() >= qw)
                readyMessages.emplace_back(messageSigs.first);

        return readyMessages;
    }

    void processNewSig(const CACSignature & sig)
    {
        m_sequences[sig.sender()] += 1;

        m_validSignatures.insert({m_state->cipher_suite().ref(sig.authContent), sig});

        const auto sender = sig.sender();
        if(sig.isWitness())
            m_signaturesCount[sig.referencedMessage].signedWitness.insert(sender);
        else if(sig.isReady())
            m_signaturesCount[sig.referencedMessage].signedReady.insert(sender);
    }

    void emitSignature(bool witnessOrReady, const MessageRef & ref)
    {
        CACSignature sig = CACSignature::sign(*m_state, m_sigCount++, witnessOrReady, ref);
        const AuthContentRef sigRef = m_state->cipher_suite().ref(sig.authContent);

        // printf("Emitting %s ref %u\n", sig.toString().c_str(),
        //     MLS_UTIL_HASH(*m_state, sig.authContent));

        m_validSignatures.insert({sigRef, sig});

        const auto sender = sig.sender();
        if(sig.isWitness())
            m_signaturesCount[sig.referencedMessage].signedWitness.insert(sender);
        else if(sig.isReady())
            m_signaturesCount[sig.referencedMessage].signedReady.insert(sender);
    }

    void broadcastMessage(bool witnessOrReady,
        const std::optional<MessageT> & message = {})
    {
        if(witnessOrReady == CACSignature::READY)
            m_hasSentReady = true;

        std::vector<mls::AuthenticatedContent> sigs;
        for(const auto & sig : m_validSignatures)
            sigs.emplace_back(sig.second.authContent);

        CACMessage msg = {
            .witnessOrReady = witnessOrReady,
            .sigs = sigs,
            .optBroadcastMessage = message
        };

        m_broadcast(msg);
    }

    std::vector<CACSignature> validSignatures()
    {
        std::vector<CACSignature> sigs;
        std::transform(m_validSignatures.begin(), m_validSignatures.end(),
            std::back_inserter(sigs),
            [](const auto & pair){ return pair.second; });

        return sigs;
    }

private:
    ExtendedMLSState * m_state = nullptr;

    const TransmitCallback m_transmit;
    const ChoiceCallback m_choice;
    const CACDeliverCallback m_deliver;
    const CACBroadcastCallback m_broadcast;

    const uint k;
    uint n, t, qw, qr;

    uint32_t m_sigCount;
    bool m_hasSentReady = false;

    // To serialize treatment of messages (handleMessage can be call recursively
    //  as broadcasts of local message directly triggers another handleMessage)
    bool m_messageQueueLock = false;
    std::queue<CACMessage<MessageT>> m_messageQueue;

    std::map<MessageRef, MessageT> m_messages; // a.k.a seen messages
    std::map<AuthContentRef, CACSignature> m_validSignatures;
    std::set<MessageRef> m_validMessages, m_seenMessages, m_waitingMessages, m_deliveredMessages;
    std::map<mls::LeafIndex, uint32_t> m_sequences;
    
    struct MessageSigs
    {
        std::set<mls::LeafIndex> signedWitness, signedReady;

        size_t witnessCount() const
        { return signedWitness.size(); }
        size_t readyCount() const
        { return signedReady.size(); }
    };
    std::map<MessageRef, MessageSigs> m_signaturesCount;
};

#endif
