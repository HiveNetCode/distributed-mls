/**
 * @file cac_signature.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Implementation of CAC Broadcast's signature based on MLS structure for
 *  authenticated content: MLSAuthenticatedContent
 */

#ifndef __CAC_SIGNATURE_HPP__
#define __CAC_SIGNATURE_HPP__

#include <cstdint>
#include <cstring>
#include <format>
#include <optional>
#include <variant>
#include <vector>

#include "bytes/bytes.h"
#include "mls/crypto.h"
#include "mls/messages.h"
#include "mls/tree_math.h"
#include "tls/tls_syntax.h"

#include "extended_mls_state.hpp"
#include "message.hpp"

struct CACSignatureData
{
    uint32_t sequence;
    uint8_t witnessOrReady;
    MessageRef messageReference;

    TLS_SERIALIZABLE(sequence, witnessOrReady, messageReference);
};

class CACSignature
{
public:
    static constexpr bool WITNESS = true, READY = false;
    static constexpr uint8_t WITNESS_CODE = 1, READY_CODE = 2;

    const uint32_t sequence;
    bool witnessOrReady;
    const MessageRef referencedMessage;

    const mls::AuthenticatedContent authContent;
    const AuthContentRef authContentRef;    // For simplicity and efficient comparison

    mls::LeafIndex sender() const
    {
        return std::get<mls::MemberSender>(authContent.content.sender.sender).sender;
    }

    bool isWitness() const { return witnessOrReady == WITNESS; }
    bool isReady()   const { return witnessOrReady == READY; }

    mls::bytes_ns::bytes marshal() const
    {
        return mls::tls::marshal(authContent);
    }

    static std::optional<CACSignature> verifyAndConvert(const ExtendedMLSState & state,
        const mls::AuthenticatedContent & authContent)
    {
        if(!state.verify(authContent)
            || authContent.content.epoch != state.epoch()
            || authContent.content.sender.sender_type() != mls::SenderType::member
            || authContent.content.content_type() != mls::ContentType::application)
        {
            return {};
        }

        const auto content = std::get<mls::ApplicationData>(authContent.content.content).data;

        CACSignatureData data;
        mls::tls::unmarshal(content, data);

        if(data.witnessOrReady != WITNESS_CODE && data.witnessOrReady != READY_CODE)
            return {};

        return { CACSignature(data.sequence, data.witnessOrReady == WITNESS_CODE,
            data.messageReference, authContent, state) };
    }

    static CACSignature sign(const ExtendedMLSState & state,
        uint32_t sequence, bool witnessOrReady,
        const MessageRef referencedMessage)
    {
        const auto authContent = state.sign(mls::tls::marshal((CACSignatureData) {
            .sequence = sequence,
            .witnessOrReady = witnessOrReady == WITNESS ? WITNESS_CODE : READY_CODE,
            .messageReference = referencedMessage
        }));
        
        return CACSignature{sequence, witnessOrReady, referencedMessage,
            authContent, state};
    }

    // Compatibility with std::set and others
    bool operator<(const CACSignature & other) const
    {
        return authContentRef < other.authContentRef;
    }

    bool operator==(const CACSignature & other) const
    {
        return authContentRef == other.authContentRef;
    }

    std::string toString() const
    {
        return std::format("(s:{},seq:{},{},{})", sender().val, sequence,
            isWitness() ? 'W' : 'R', MLS_UTIL_HASH_REF(referencedMessage));
    }

private:
    // We only allow construction of valid CACSignature objects
    CACSignature(uint32_t sequence, bool witnessOrReady,
        const MessageRef & messageReference,
        const mls::AuthenticatedContent & authContent,
        const ExtendedMLSState & state)
        : sequence(sequence), witnessOrReady(witnessOrReady),
            referencedMessage(messageReference), authContent(authContent),
            authContentRef(state.cipher_suite().ref(authContent))
    { }
};

#endif
