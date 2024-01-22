/**
 * @file mls_client.cpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief MLS Client for benchmarks
 * 
 * Usage: ./mls_client <identity> <pki-addr> <network-rtt>
 *  - identity:    unique string identifier for the client
 *  - pki-addr:    address of the pki to be used
 *  - network-rtt: rtt with the farthest client in the network (in ms)
 *      -> after submitting proposal and waiting one rtt, client will commit
 * 
 * Commands:
 *  - Create
 *  - Update
 *  - Add <identity>
 *  - Remove <identity>
 *
 * Output: traces of cpu time, size of messages and number of messages
 *      TBD
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <iostream>
#include <netinet/in.h>
#include <optional>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <variant>
#include <vector>

#include "bytes/bytes.h"
#include "mls/common.h"
#include "mls/core_types.h"
#include "mls/credential.h"
#include "mls/crypto.h"
#include "mls/messages.h"
#include "mls/state.h"
#include "tls/tls_syntax.h"

#include "check.hpp"
#include "distributed_ds.hpp"
#include "extended_mls_state.hpp"
#include "gossip_bcast.hpp"
#include "message.hpp"
#include "network.hpp"
#include "pki.hpp"
#include "pki_client.hpp"

const mls::bytes_ns::bytes GROUP_ID = {0xAB, 0xCD};
const mls::CipherSuite SUITE { mls::CipherSuite::ID::X448_AES256GCM_SHA512_Ed448 };

const mls::MessageOpts securedMessageOptions{ true, {}, 0 };

class MLSClient
{
public:
    MLSClient(const mls::CipherSuite & suite, const mls::bytes_ns::bytes & id,
        Network & network, const char * pkiAddress, int networkRtt)
        : initKey(mls::HPKEPrivateKey::generate(suite)),
            leafKey(mls::HPKEPrivateKey::generate(suite)),
            identityKey(mls::SignaturePrivateKey::generate(suite)),
            leafNode(suite, leafKey.public_key, identityKey.public_key,
                mls::Credential::basic(id), mls::Capabilities::create_default(),
                mls::Lifetime::create_default(), {}, identityKey),
            keyPackage(suite, initKey.public_key, leafNode, {}, identityKey),
            network(network), pkiAddress(pkiAddress), networkRtt(networkRtt),
            dds(network, networkRtt,
                std::bind(&MLSClient::handleWelcome, this, std::placeholders::_1),
                std::bind(&MLSClient::handleProposalOrMessage, this, std::placeholders::_1),
                std::bind(&MLSClient::handleCommit, this, std::placeholders::_1), id, suite)
    { }

    void create(const mls::bytes_ns::bytes & groupId)
    {
        if(state)
            return;

        state = {{mls::State{groupId, keyPackage.cipher_suite, leafKey, identityKey, leafNode, {}}}};

        dds.init(&state.value());

        // TODO Initial credentials should be deleted (for Forward Secrecy)
    }

    void add(const std::string & ids)
    {
        // Split string to allow multiple adds (using ',')

        std::istringstream iss(ids);

        std::string id;
        while(std::getline(iss, id, ','))
        {
            PKIQueryResponse resp = queryPKI(pkiAddress, id);
            if(!resp.success)
                printf("User not found: %s\n", id.c_str());
            else
            {
                std::vector<uint8_t> packageBytes = {resp.preKey.content, resp.preKey.content + resp.preKey.size};

                mls::KeyPackage keyPackage;
                mls::tls::unmarshal(packageBytes, keyPackage);

                mls::MLSMessage proposal = state->add(keyPackage, securedMessageOptions);
                dds.broadcastProposalOrMessage(proposal);
            }
        }
    }

    void remove(const std::string & id)
    {
        std::vector<uint8_t> idBytes{id.begin(), id.end()};
        const auto proposal = state->remove(idBytes, securedMessageOptions);

        if(proposal)
        {
            dds.broadcastProposalOrMessage(proposal.value());
        }
    }

    void update()
    {
        const auto proposal = state->update(mls::HPKEPrivateKey::generate(state->cipher_suite()), {}, securedMessageOptions);

        dds.broadcastProposalOrMessage(proposal);
    }

    void message(const std::string & message)
    {
        std::vector<uint8_t> messageBytes{message.begin(), message.end()};
        const auto protectedMessage = state->protect({}, messageBytes, 0);

        dds.broadcastProposalOrMessage(protectedMessage);
    }

    void commit()
    {
        // Copy the state to avoid side-effects of removeSelfUpdate()
        ExtendedMLSState copyState = state.value();
        copyState.removeSelfUpdate();

        auto [commit, welcome, newState] = copyState.commit(copyState.freshSecret(), 
            mls::CommitOpts{ {}, true, true, {} }, securedMessageOptions);

        m_proposedCommit = { commit };
        m_associatedState = { newState };
        
        dds.proposeCommit(commit, welcome);
    }

    ExtendedMLSState * handleWelcome(const mls::Welcome & welcome)
    {
        if(state)
            return nullptr;

        state = {{mls::State{initKey, leafKey, identityKey, keyPackage, welcome, std::nullopt, {}}}};

        for(const auto & member : state->getMembersIdentity())
        {
            std::string memberId{(const char *) member.data(), member.size()};
            network.connect(memberId);
        }

        printf("Joined group epoch %ld\n", state->epoch());
        fflush(stdout);

        // TODO Initial credentials should be deleted (for Forward Secrecy)

        return &state.value();
    }

    void handleProposalOrMessage(const mls::MLSMessage & message)
    {
        const auto appMessage = state->isValidApplicationMessage(message);
        if(appMessage)
        {
            auto [authData, messageBytes] = state->unprotect(message);
            printf("Message: %.*s\n", (int) messageBytes.size(), messageBytes.data());
            fflush(stdout);
        }
        else if(state->isValidProposal(message))
        {
            bool proposalFromSelf = state->isProposalFromSelf(message); // Read proposal before handle (otherwise function should read from cached proposals ?)
            state->handle(message);

            if(!m_commitTimeout && !m_proposedCommit)
            {
                int delay = proposalFromSelf ? networkRtt : 2 * networkRtt;

                m_commitTimeout = network.registerTimeout(delay, [this](const auto &)
                {
                    m_commitTimeout = {};
                    commit();
                });
            }
        }
    }

    ExtendedMLSState * handleCommit(const mls::MLSMessage & message)
    {
        if(state->isValidCommit(message))
        {
            auto [added, removed] = state->getCommitMembershipChanges(message);

            // printf("Accepted commit %u\n", MLS_UTIL_HASH(*state, message));

            // const auto [sender, proposals] = state->getCommitContent(message);
            // printf("Commit by %d:", sender.val);
            // for(const auto & proposal : proposals)
            //     std::visit(mls::overloaded{
            //         [](const mls::Add & add)
            //         {
            //             const auto id = add.key_package.leaf_node.credential.get<mls::BasicCredential>().identity;
            //             printf("\tAdd %.*s", id.size(), id.data());
            //         },
            //         [](const mls::Remove & remove)
            //         {
            //             printf("\tRemove %d", remove.removed.val);
            //         },
            //         [](const mls::Update & update)
            //         {
            //             const auto id = update.leaf_node.credential.get<mls::BasicCredential>().identity;
            //             printf("\tUpdate %.*s", id.size(), id.data());
            //         },
            //         [](const mls::PreSharedKey &){ return; },
            //         [](const mls::ReInit &){ return; },
            //         [](const mls::ExternalInit &){ return; },
            //         [](const mls::GroupContextExtensions &){ return; }
            //     }, proposal.content);
            // printf("\n");

            for(const auto & addedId : added)
            {
                printf("Added: %.*s\n", (int) addedId.size(), addedId.data());
                network.connect(std::string{(const char *) addedId.data(), addedId.size()});
            }

            for(const auto & removedId : removed)
            {
                printf("Removed %.*s\n", (int) removedId.size(), removedId.data());
                network.disconnect(std::string{(const char *) removedId.data(), removedId.size()});
            }

            if(m_proposedCommit
                && state->cipher_suite().ref(message) == state->cipher_suite().ref(m_proposedCommit.value()))
            {
                state = m_associatedState;
                printf("Local commit new epoch %ld id %u\n", state->epoch(),
                    MLS_UTIL_HASH_STATE(*state));
            }
            else
            {
                auto newState = state->handle(message);
                if(!newState)
                    sys_error("Invalid commit\n");

                state = ExtendedMLSState{newState.value()};
                printf("Remote commit new epoch %ld id %u\n", state->epoch(),
                    MLS_UTIL_HASH_STATE(*state));
            }
            fflush(stdout);
            
            // Clean the state
            m_proposedCommit = {};
            m_associatedState = {};
            if(m_commitTimeout)
            {
                network.unregisterTimeout(m_commitTimeout.value());
                m_commitTimeout = {};
            }

            return &state.value();
        }

        return nullptr;
    }

    void handleMessage(Bytes & rawMessage)
    {
        dds.receiveNetworkMessage(rawMessage);
    }

    mls::KeyPackage getKeyPackage()
    {
        return keyPackage;
    }

private:
    mls::HPKEPrivateKey initKey, leafKey;
    mls::SignaturePrivateKey identityKey;
    mls::LeafNode leafNode;
    mls::KeyPackage keyPackage;

    Network & network;
    const char * pkiAddress;
    const int networkRtt;

    DistributedDeliveryService dds;

    std::optional<mls::MLSMessage> m_proposedCommit = {};
    std::optional<ExtendedMLSState> m_associatedState = {};

    std::optional<timeoutID> m_commitTimeout = {};

    std::optional<ExtendedMLSState> state;
};

int main(int argc, char * argv[])
{
    if(argc < 4)
    {
        fprintf(stderr, "usage: %s <identity> <pki-addr> <network-rtt>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char * clientIdentity = argv[1];
    const char * pkiAddress = argv[2];
    const int networkRtt = atoi(argv[3]);

    // TODO We may set a seed, gossip communications relies on rand() for sampling
    srand(time(0) + std::hash<const char *>()(clientIdentity));

    int server = socket(AF_INET, SOCK_STREAM, 0);
    PCHECK(server);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr =
            { .s_addr = INADDR_ANY }
    };

    if(bind(server, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) == -1)
        sys_error("Error binding socket to port");

    socklen_t addrLen = sizeof(struct sockaddr_in);
    if(getsockname(server, (struct sockaddr *) &addr, &addrLen) == -1)
        sys_error("Error getting server socket info");

    if(listen(server, 1000) == -1)
        sys_error("Error listening to socket");

    mls::bytes_ns::bytes clientIdBytes{{clientIdentity, clientIdentity + strlen(clientIdentity)}};

    Network net(pkiAddress, server);

    MLSClient client{ SUITE, clientIdBytes, net, pkiAddress, networkRtt };
    net.setHandleMessage([&](Bytes & message)
    {
        client.handleMessage(message);
    });

    auto keyPackageBytes = marshalToBytes(client.getKeyPackage());
    publishToPKI(pkiAddress, addr, std::string{clientIdentity, strlen(clientIdentity)}, keyPackageBytes);

    printf("Client is running, you can now use the commands: create, add, remove, update and message\n");

    net.runSelect([&]()
    {
        std::string line;
        std::getline(std::cin, line);

        std::istringstream iss(line);
        std::string command, arg;

        iss >> command >> std::ws;
        std::getline(iss, arg);

        if(command == "create")
            client.create(GROUP_ID);
        else if(command == "add" || command == "remove" || command == "message")
        {
            if(arg.empty())
                printf("Error: missing argument for command %s\n", command.c_str());
            else
            {
                if(command == "add")
                    client.add(arg);
                else if(command == "remove")
                    client.remove(arg);
                else if(command == "message")
                    client.message(arg);
            }
        }
        else if(command == "update")
            client.update();
        else if(command == "stop")
            return false;
        else
            printf("Invalid command\n");

        return true; // Client did not stop
    });

    return 0;
}
