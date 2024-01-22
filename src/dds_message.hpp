/**
 * @file dds_message.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Read and write Distributed Delivery Service messages
 */

/* Protocol specification

DDSMessage:
{
    type: u8,
    select(type)
    {
        case WELCOME:           WelcomeMessage,
        case GOSSIP_BCAST:      GossipBroadcastMessage,
        case CASCADE_CONSENSUS: MLSMessage<CascadeConsensusMessage> // MLS Encapsulated to protect message and control epochs flow
    }
}

WelcomeMessage:
{
    mls_welcome: bytes
}

GossipBroadcast:
{
    type: u8,
    select(type)
    {
        case SUBSCRIBE: { identity: bytes }, // TODO In better setting, just subscribe on current p2p link. Only think that is not secure/signed
        case GOSSIP:    MLSMessage // Proposal or app message, commit should not be allowed
    }
}

CascadeConsensusMessage:
{
    type: u8,
    instance: u8,
    select(type)
    {
        case CAC: CACMessage,
        case RC:  RCMessage,
        case FC:  FCMessage
    }
}

CACMessage:
{
    type: u8,
    if(type == WITNESS)
    {
        sigs: list<CACSignature>,
        bcastMessage: optional<MLSMessage> // Commit
    }
    else if(type == READY)
    {
        sigs: list<CACSignature>
    }
}

CACSignature: MLSAuthenticatedContent<{ seq: u32, witOrReady: u8, messageHash: bytes }>
// TODO Consider a lighter structure: MLSAuthContent contains unnecessary fields in this context

RCMessage: TBD
FCMessage: TBD

Misc:

list<T>:
{
    count: u32,
    values: T[count]
}

optional<T>:
{
    present: u8,
    if(present)
    {
        content: T
    }
}

*/

#ifndef __DDS_MESSAGE_HPP__
#define __DDS_MESSAGE_HPP__

#include "message.hpp"

#include <cstdint>
#include <cstring>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "bytes/bytes.h"
#include "mls/messages.h"
#include "mls/state.h"
#include "mls/tree_math.h"
#include "tls/tls_syntax.h"

#include "cac_signature.hpp"
#include "extended_mls_state.hpp"
#include "network.hpp"

enum DDSMessageType : uint8_t
{
    DDS_WELCOME = 1,
    DDS_GOSSIP_BCAST,
    DDS_CASCADE_CONSENSUS
};

enum GossipBcastMessageType : uint8_t
{
    GOSSIP_SUBSCRIBE = 1, // TODO Handle unsubscribe ?
    GOSSIP_GOSSIP
};

struct GossipBcastMessage
{
    std::variant<mls::bytes_ns::bytes, mls::MLSMessage> content;

    GossipBcastMessageType type() const
    { return mls::tls::variant<GossipBcastMessageType>::type(content); }

    bool isSubscribe() const
    { return type() == GOSSIP_SUBSCRIBE; }
    bool isGossip() const
    { return type() == GOSSIP_GOSSIP; }

    const mls::bytes_ns::bytes & subscriberId() const
    { return std::get<mls::bytes_ns::bytes>(content); }
    const mls::MLSMessage & bcastMessage() const
    { return std::get<mls::MLSMessage>(content); }

    TLS_SERIALIZABLE(content);
    TLS_TRAITS(mls::tls::variant<GossipBcastMessageType>);
};

enum CascadeConsensusMessageType : uint8_t
{
    CASCADE_CONSENSUS_CAC = 1,
    CASCADE_CONSENSUS_RC,       /** Restrained Consensus */
    CASCADE_CONSENSUS_CAC_2,    /** CAC Broadcast of RC Results */
    CASCADE_CONSENSUS_FC        /** Full consensus */
};

template <typename T>
struct CACMessage
{
    bool witnessOrReady;
    std::vector<mls::AuthenticatedContent> sigs;
    std::optional<T> optBroadcastMessage;

    bool isWitness() const
    { return witnessOrReady == CACSignature::WITNESS; }
    bool isReady() const
    { return witnessOrReady == CACSignature::READY; }

    bool hasBroadcastMessage() const
    { return optBroadcastMessage.has_value(); }
    const T & broadcastMessage() const
    { return optBroadcastMessage.value(); }

    TLS_SERIALIZABLE(witnessOrReady, sigs, optBroadcastMessage);
};

enum RestrainedConsensusMessageType : uint8_t
{
    RESTRAINED_CONSENSUS_PARTICIPATE = 1,
    RESTRAINED_CONSENSUS_RETRACT
};

struct RestrainedConsContent
{
    std::vector<mls::AuthenticatedContent> sigSet;
    std::vector<std::vector<std::pair<mls::LeafIndex, MessageRef>>> powerConflictSet;
    std::vector<mls::AuthenticatedContent> proofs;

    TLS_SERIALIZABLE(sigSet, powerConflictSet, proofs);
};

struct RestrainedConsensusMessage
{
    std::variant<RestrainedConsContent, mls::AuthenticatedContent> content;

    RestrainedConsensusMessageType type() const
    { return mls::tls::variant<RestrainedConsensusMessageType>::type(content); }

    bool isRestrainedCons() const
    { return type() == RESTRAINED_CONSENSUS_PARTICIPATE; }
    bool isRetract() const
    { return type() == RESTRAINED_CONSENSUS_RETRACT; }

    const RestrainedConsContent & restrainedCons() const
    { return std::get<RestrainedConsContent>(content); }
    const mls::AuthenticatedContent & retract() const
    { return std::get<mls::AuthenticatedContent>(content); }

    TLS_SERIALIZABLE(content);
    TLS_TRAITS(mls::tls::variant<RestrainedConsensusMessageType>);
};

struct CAC2Content
{
    std::vector<MessageRef> conflictingMessages;
    std::vector<mls::AuthenticatedContent> signatures;

    TLS_SERIALIZABLE(conflictingMessages, signatures);
};

enum ConsensusMessageType : uint8_t
{
    CONSENSUS_PROPOSE = 1,
    CONSENSUS_PRE_PREPARE,
    CONSENSUS_PREPARE,
    CONSENSUS_COMMIT,
    CONSENSUS_VIEW_CHANGE
};

template <typename T>
struct ConsensusProposeMessage
{
    uint32_t view;
    T content;
    TLS_SERIALIZABLE(view, content);
};

struct ConsensusMessageContent
{
    uint32_t view;
    MessageRef consensusMessage;
    TLS_SERIALIZABLE(view, consensusMessage);
};

template <typename T>
struct ConsensusPrePrepareMessage
{
    mls::AuthenticatedContent signedContent;
    T proposedMessage;
    TLS_SERIALIZABLE(signedContent, proposedMessage);
};

struct ConsensusPrepareMessage
{
    mls::AuthenticatedContent signedContent;
    TLS_SERIALIZABLE(signedContent);
};

struct ConsensusCommitMessage
{
    mls::AuthenticatedContent signedContent;
    TLS_SERIALIZABLE(signedContent);
};

struct ViewChangeMessageContent
{
    uint32_t view;
    TLS_SERIALIZABLE(view);
};

template <typename T>
struct ConsensusMessage
{
    std::variant<ConsensusProposeMessage<T>, ConsensusPrePrepareMessage<T>,
        ConsensusPrepareMessage, ConsensusCommitMessage,
        mls::AuthenticatedContent> content;

    ConsensusMessageType type() const
    { return mls::tls::variant<ConsensusMessageType>::type(content); }

    const ConsensusProposeMessage<T> & proposeMessage() const
    { return std::get<ConsensusProposeMessage<T>>(content); };
    const ConsensusPrePrepareMessage<T> & prePrepareMessage() const
    { return std::get<ConsensusPrePrepareMessage<T>>(content); }
    const ConsensusPrepareMessage & prepareMessage() const
    { return std::get<ConsensusPrepareMessage>(content); }
    const ConsensusCommitMessage & commitMessage() const
    { return std::get<ConsensusCommitMessage>(content); }
    const mls::AuthenticatedContent & viewChange() const
    { return std::get<mls::AuthenticatedContent>(content); }

    TLS_SERIALIZABLE(content);
    TLS_TRAITS(mls::tls::variant<ConsensusMessageType>);
};

struct CascadeConsensusMessage
{
    uint8_t instance;
    std::variant<
        CACMessage<mls::MLSMessage>, CACMessage<CAC2Content>,
        RestrainedConsensusMessage, ConsensusMessage<CAC2Content>> content;

    CascadeConsensusMessageType type() const
    { return mls::tls::variant<CascadeConsensusMessageType>::type(content); }

    bool isCAC() const
    { return type() == CASCADE_CONSENSUS_CAC; }
    bool isCAC2() const
    { return type() == CASCADE_CONSENSUS_CAC_2; }
    bool isRestrainedConsensus() const
    { return type() == CASCADE_CONSENSUS_RC; }
    bool isFullConsensus() const
    { return type() == CASCADE_CONSENSUS_FC; }

    const CACMessage<mls::MLSMessage> & cacMessage() const
    { return std::get<CACMessage<mls::MLSMessage>>(content); }
    const CACMessage<CAC2Content> & cac2Message() const
    { return std::get<CACMessage<CAC2Content>>(content); }
    const RestrainedConsensusMessage & restrainedConsensusMessage() const
    { return std::get<RestrainedConsensusMessage>(content); }
    const ConsensusMessage<CAC2Content> & fullConsensusMessage() const
    { return std::get<ConsensusMessage<CAC2Content>>(content); }

    TLS_SERIALIZABLE(instance, content);
    TLS_TRAITS(mls::tls::pass, mls::tls::variant<CascadeConsensusMessageType>);
};

struct DDSMessage
{
    std::variant<mls::Welcome, GossipBcastMessage, mls::MLSMessage> content;

    DDSMessageType type() const
    { return mls::tls::variant<DDSMessageType>::type(content); }

    bool isWelcome() const
    { return type() == DDS_WELCOME; }
    bool isGossip() const
    { return type() == DDS_GOSSIP_BCAST; }
    bool isCascadeConsensus() const
    { return type() == DDS_CASCADE_CONSENSUS; }

    const mls::Welcome & welcome() const
    { return std::get<mls::Welcome>(content); }
    const GossipBcastMessage & gossipMessage() const
    { return std::get<GossipBcastMessage>(content); }
    const mls::MLSMessage & cascadeConsensusMessage() const
    { return std::get<mls::MLSMessage>(content); }

    TLS_SERIALIZABLE(content);
    TLS_TRAITS(mls::tls::variant<DDSMessageType>);
};

namespace mls::tls
{
    TLS_VARIANT_MAP(GossipBcastMessageType, mls::bytes_ns::bytes, GOSSIP_SUBSCRIBE);
    TLS_VARIANT_MAP(GossipBcastMessageType, mls::MLSMessage, GOSSIP_GOSSIP);

    TLS_VARIANT_MAP(RestrainedConsensusMessageType, RestrainedConsContent,
        RESTRAINED_CONSENSUS_PARTICIPATE);
    TLS_VARIANT_MAP(RestrainedConsensusMessageType, mls::AuthenticatedContent,
        RESTRAINED_CONSENSUS_RETRACT);

    TLS_VARIANT_MAP(ConsensusMessageType, ConsensusProposeMessage<CAC2Content>,
        CONSENSUS_PROPOSE);
    TLS_VARIANT_MAP(ConsensusMessageType, ConsensusPrePrepareMessage<CAC2Content>,
        CONSENSUS_PRE_PREPARE);
    TLS_VARIANT_MAP(ConsensusMessageType, ConsensusPrepareMessage, CONSENSUS_PREPARE);
    TLS_VARIANT_MAP(ConsensusMessageType, ConsensusCommitMessage,CONSENSUS_COMMIT);
    TLS_VARIANT_MAP(ConsensusMessageType, mls::AuthenticatedContent, CONSENSUS_VIEW_CHANGE);

    TLS_VARIANT_MAP(CascadeConsensusMessageType, CACMessage<MLSMessage>, CASCADE_CONSENSUS_CAC);
    TLS_VARIANT_MAP(CascadeConsensusMessageType, CACMessage<CAC2Content>,
        CASCADE_CONSENSUS_CAC_2);
    TLS_VARIANT_MAP(CascadeConsensusMessageType, RestrainedConsensusMessage,
        CASCADE_CONSENSUS_RC);
    TLS_VARIANT_MAP(CascadeConsensusMessageType, ConsensusMessage<CAC2Content>,
        CASCADE_CONSENSUS_FC);

    TLS_VARIANT_MAP(DDSMessageType, mls::Welcome, DDS_WELCOME);
    TLS_VARIANT_MAP(DDSMessageType, GossipBcastMessage, DDS_GOSSIP_BCAST);
    TLS_VARIANT_MAP(DDSMessageType, mls::MLSMessage, DDS_CASCADE_CONSENSUS);
}

// Add TLS serialization support for pairs
namespace mls::tls
{
    // Pair writer
    template <typename T1, typename T2>
    ostream &
    operator<<(ostream & str, const std::pair<T1, T2> & pair)
    {
        str << pair.first;
        str << pair.second;
        return str;
    }

    // Pair reader
    template <typename T1, typename T2>
    istream &
    operator>>(istream & in, std::pair<T1, T2> & pair)
    {
        in >> pair.first;
        in >> pair.second;
        return in;
    }
}

#endif
