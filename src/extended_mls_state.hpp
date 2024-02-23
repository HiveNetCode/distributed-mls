/**
 * @file extended_mls_state.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Extend MLS State to add necessary functions
 */

#ifndef __EXTENDED_MLS_STATE_HPP__
#define __EXTENDED_MLS_STATE_HPP__

#include <mls/state.h>

#include <cstdint>
#include <exception>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <variant>
#include <vector>

#include <bytes/bytes.h>

#include <mls/common.h>
#include <mls/core_types.h>
#include <mls/credential.h>
#include <mls/crypto.h>
#include <mls/messages.h>
#include <mls/tree_math.h>
#include "tls/tls_syntax.h"

#include "message.hpp"

using MessageRef = mls::bytes_ns::bytes;
using AuthContentRef = mls::bytes_ns::bytes;

#define MLS_UTIL_HASH(S, M) (*((uint32_t *) &(S).cipher_suite().ref(M).data()[5]))
#define MLS_UTIL_HASH_STATE(S) (*((uint32_t *) &(S).epoch_authenticator().data()[5]))
#define MLS_UTIL_HASH_REF(R) (*((uint32_t *) &(R).data()[5]))

class ExtendedMLSState
    : public mls::State
{
public:
    ExtendedMLSState(const mls::State & state)
        : mls::State(state)
    { }

    /** Returns proposal reference if valid */
    std::optional<mls::ProposalRef> isValidProposal(const mls::MLSMessage & message)
    {
        if(message.epoch() != epoch())
            return {};

        auto optContent = checkAndExtractContent(message, mls::ContentType::proposal);
        if(optContent)
            return {cipher_suite().ref(optContent.value())};
        else
            return {};
    }

    /** Returns referenced proposals if valid */
    std::optional<std::set<mls::ProposalRef>> isValidCommit(const mls::MLSMessage & message)
    {
        if(message.epoch() != epoch())
            return {};

        auto optContent = checkAndExtractContent(message, mls::ContentType::commit);
        if(optContent)
        {
            std::set<mls::ProposalRef> proposalRefs;

            const auto& commit = std::get<mls::Commit>(optContent->content.content);
            for(const auto& proposal : commit.proposals)
                if(std::holds_alternative<mls::ProposalRef>(proposal.content))
                    proposalRefs.insert(std::get<mls::ProposalRef>(proposal.content));

            return proposalRefs;
        }
        else
            return {};
    }

    /** Returns message content if valid */
    std::optional<mls::bytes_ns::bytes> isValidApplicationMessage(const mls::MLSMessage & message)
    {
        if(message.epoch() != epoch())
            return {};

        auto optContent = checkAndExtractContent(message, mls::ContentType::application);
        if(optContent)
        {
            return {var::get<mls::ApplicationData>(optContent->content.content).data};
        }
        else
            return {};
    }

    std::vector<mls::bytes_ns::bytes> getMembersIdentity(bool excludeSelf = false) const
    {
        std::vector<mls::bytes_ns::bytes> identities;

        tree().all_leaves([&](auto index, const mls::LeafNode& leaf)
        {
            if(!excludeSelf || index != this->index())
                identities.emplace_back(leaf.credential.get<mls::BasicCredential>().identity);
            return true;
        });

        return identities;
    }

    std::vector<mls::LeafIndex> getMembersIndexes() const
    {
        std::vector<mls::LeafIndex> indexes;

        tree().all_leaves([&](auto index, auto)
        {
            indexes.emplace_back(index);
            return true;
        });
        return indexes;
    }

    std::optional<mls::MLSMessage> remove(const mls::bytes_ns::bytes & identity,
        const mls::MessageOpts & msg_opts)
    {
        mls::LeafIndex toRemoveIdx;

        bool found = tree().any_leaf([&](auto idx, const mls::LeafNode& leaf)
        {
            if(leaf.credential.get<mls::BasicCredential>().identity == identity)
            {
                toRemoveIdx = idx;
                return true;
            }
            else
                return false;
        });

        if(found)
            return {State::remove(toRemoveIdx, msg_opts)};
        else
            return {};
    }

    std::pair<std::vector<mls::bytes_ns::bytes>, std::vector<mls::bytes_ns::bytes>>
    getCommitMembershipChanges(const mls::MLSMessage & message)
    {
        std::vector<mls::bytes_ns::bytes> identitiesAdded, identitiesRemoved;

        // Build structure for efficient search
        std::map<mls::ProposalRef, mls::Proposal> proposalsByRef;
        for(const auto& proposal : _pending_proposals)
            proposalsByRef[proposal.ref] = proposal.proposal;

        const auto commit = checkAndExtractContent(message, mls::ContentType::commit);
        if(commit)
        {
            const auto proposals = std::get<mls::Commit>(commit->content.content).proposals;

            auto checkProposal = [&](const mls::Proposal & proposal)
            {
                if(proposal.proposal_type() == mls::ProposalType::add)
                {
                    identitiesAdded.emplace_back(
                        std::get<mls::Add>(proposal.content)
                            .key_package
                            .leaf_node
                            .credential
                            .get<mls::BasicCredential>()
                            .identity
                    );
                }
                else if(proposal.proposal_type() == mls::ProposalType::remove)
                {
                    const mls::Remove & remove = std::get<mls::Remove>(proposal.content);
                    
                    identitiesRemoved.emplace_back(
                        tree()
                            .node_at(remove.removed)
                            .leaf_node()
                            .credential
                            .get<mls::BasicCredential>()
                            .identity
                    );
                }
            };

            for(const auto & proposal : proposals)
                std::visit(mls::overloaded{
                    [&checkProposal](const mls::Proposal & proposal)
                    {
                        checkProposal(proposal);
                    },
                    [&checkProposal, &proposalsByRef](const mls::ProposalRef & proposalRef)
                    {
                        checkProposal(proposalsByRef[proposalRef]);
                    }
                }, proposal.content);
        }

        return {identitiesAdded, identitiesRemoved};
    }

    std::pair<mls::LeafIndex, std::vector<mls::Proposal>>
    getCommitContent(const mls::MLSMessage & message)
    {
        auto optContent = checkAndExtractContent(message, mls::ContentType::commit);
        
        mls::LeafIndex sender = std::get<mls::MemberSender>(optContent->content.sender.sender).sender;
        std::vector<mls::Proposal> proposals;

        // Build structure for efficient search
        std::map<mls::ProposalRef, mls::Proposal> proposalsByRef;
        for(const auto& proposal : _pending_proposals)
            proposalsByRef[proposal.ref] = proposal.proposal;

        for(const auto & proposal : std::get<mls::Commit>(optContent->content.content).proposals)
        {
            std::visit(mls::overloaded{
                [&proposals](const mls::Proposal & proposal)
                { proposals.emplace_back(proposal); },
                [&proposals, &proposalsByRef](const mls::ProposalRef & proposalRef)
                { proposals.emplace_back(proposalsByRef[proposalRef]); }
            }, proposal.content);
        }

        return { sender, proposals };
    }

    mls::LeafIndex getCommitSender(const mls::MLSMessage & message)
    {
        auto optContent = checkAndExtractContent(message, mls::ContentType::commit);

        return std::get<mls::MemberSender>(optContent->content.sender.sender).sender;
    }

    const mls::bytes_ns::bytes getMemberNameByIndex(const mls::LeafIndex & idx)
    {
        return tree().leaf_node(idx)->credential.get<mls::BasicCredential>().identity;
    } 

    inline bytes freshSecret()
    {
        return mls::hpke::random_bytes(_suite.secret_size());
    }

    void removeSelfUpdate()
    {
        for(auto proposalsIt = _pending_proposals.begin(); proposalsIt != _pending_proposals.end(); )
        {
            if(proposalsIt->proposal.proposal_type() == mls::ProposalType::update
                && proposalsIt->sender == _index)
                proposalsIt = _pending_proposals.erase(proposalsIt);
            else
                proposalsIt++;
        }
    }

    bool isProposalFromSelf(const mls::MLSMessage & message)
    {
        const auto optContent = checkAndExtractContent(message, mls::ContentType::proposal);
        if(!optContent)
            return false;

        const auto sender = optContent->content.sender;
        if(sender.sender_type() != mls::SenderType::member)
            return false;

        const auto memberSender = std::get<mls::MemberSender>(sender.sender);
        return memberSender.sender == index();
    }

    // Allow client to sign any type of content
    mls::AuthenticatedContent sign(const mls::bytes_ns::bytes & content) const
    {
        return mls::State::sign({ mls::MemberSender{ _index } },
            std::forward<mls::ApplicationData>({ content }), {}, true /** Mandatory to be true even though we only sign */);
    }

    // Expose list of received proposals, to be committed
    const std::list<CachedProposal> & cachedProposals() const
    {
        return _pending_proposals;
    }

    // Just expose the ability of verifying authenticated contents
    bool verify(const mls::AuthenticatedContent & authContent) const
    {
        return mls::State::verify(authContent);
    }

    template <typename T>
    std::optional<T> verifyAndExtract(const mls::AuthenticatedContent & authContent)
    {
        if(!verify(authContent)
            || authContent.content.content_type() != mls::ContentType::application)
            return {};

        T content;
        mls::tls::unmarshal(std::get<mls::ApplicationData>(
            authContent.content.content).data, content);

        return content;
    }

protected:
    std::optional<mls::AuthenticatedContent> checkAndExtractContent(
        const mls::MLSMessage & message, const mls::ContentType & type)
    {
        mls::AuthenticatedContent authContent;

        try
        {
            ExtendedMLSState stateCopy = *this;
            authContent = stateCopy.unprotect_to_content_auth(message);
        }
        catch (std::exception& e)
        {
            printf("MLS Read Exception: %s\n", e.what());
            return {};
        }

        if(authContent.content.content_type() != type)
            return {};

        return authContent;
    }

};

template <typename T>
static void unmarshal(const Bytes & bytes, T & message)
{
    std::vector<uint8_t> messageBytes{bytes.content, bytes.content + bytes.size};
    mls::tls::unmarshal(messageBytes, message);
}

static Bytes toBytes(const mls::bytes_ns::bytes & bytes)
{
    Bytes res{bytes.size()};
    memcpy(res.content, bytes.data(), bytes.size());

    return res;
}

template <typename T>
static Bytes marshalToBytes(const T & message)
{
    mls::bytes_ns::bytes marshaledMessage = mls::tls::marshal(message);
    return toBytes(marshaledMessage);
}

#endif
