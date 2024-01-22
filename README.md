
# Distributed MLS Client

Proof of concept demonstrating an MLS (Messaging Layer Security, RFC 9420) client that can operate in a fully distributed manner. This is the concept described in the following article:

*Ludovic Paillat, Claudia-Lavinia Ignat, Davide Frey, Mathieu Turuani, Amine Ismail. Design of an Efficient Distributed Delivery Service for Group Key Agreement Protocols. FPS 2023 - 16th International Symposium on Foundations & Practice of Security, Dec 2023, Bordeaux, France. pp.1-16. [hal-04337821](https://inria.hal.science/hal-04337821/)*

This project is based on Cisco's implementation of MLS: [cisco/mlspp](https://github.com/cisco/mlspp).

## Build

First, clone the project using the following command
```bash
git clone https://github.com/HiveNetCode/distributed-mls.git --recursive
```

### Dependencies

The `mlspp` project requires two dependencies to be installed prior to compilation:

* `openssl`
* `nlohmann-json`

### Compilation

The project and `mlspp` can be compiled directly by running the following command:
```bash
make
```

## Usage

First, to be able to run clients, one must run a PKI instance with the following command:
```bash
bin/pki
```

In our settings, the PKI has two roles:
* storing clients' `KeyPackage` that will be use by other users to invite them in the group,
* providing clients' address to allow other clients to communicate with them.

In a P2P network, this PKI could be replaced by distributed mechanisms such as a DHT (Distributed Hash Table).

Then, one can run MLS clients by providing the following parameters:

* a user-friendly (and unique) name for the client,
* the IP address or hostname of the PKI,
* the network estimated RTT in milliseconds (i.e. the estimated round-trip time between the most distant clients).

```bash
bin/mls_client client1 127.0.0.1 300
```

Then, the client provides five commands:

* `create` allows to create an empty group. This operation is mandatory before inviting other members into the user's group. On the other hand, invited members must not have called `create`.
* `add <user>` allows to add a given member to the group and send him an invitation.
* `remove <user>` allows to remove a given member from the group.
* `update` performs an MLS Post-Compromise update of the current member.
* `message <message>` allows to send a message to all group members. This message will be sent end-to-end encrypted to group members as the purpose of the MLS Protocol.
