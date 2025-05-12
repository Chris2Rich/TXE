#ifndef _NETWORKING_H
#define _NETWORKING_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> // For timestamps

// Include Socket headers
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h> // For non-blocking sockets
#include <errno.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#define WSAEWOULDBLOCK EWOULDBLOCK // Map error codes for cross-platform compatibility
#endif

// Assumed dependencies (need actual definitions)
#include "block.h"
#include "tx.h"
#include "utils.h"

// --- Constants & Configuration ---

#define DEFAULT_P2P_PORT 8333
#define MAX_PEERS 125
#define MAX_INBOUND_CONNECTIONS 117
#define MAX_OUTBOUND_CONNECTIONS 8
#define NETWORK_MAGIC 0xD9B4BEF9
#define MAX_MSG_SIZE (1024 * 1024 * 2)
#define MAX_INV_ENTRIES 50000
#define MAX_BLACKLIST_IPS 1000
#define SOCKET_TIMEOUT_SEC 60 // Timeout for socket operations

// Forward declarations for message payload structures (should be defined properly)
typedef struct { /* ... fields ... */ } VersionPayload;
typedef struct { /* ... fields ... */ } AddrPayload;
typedef struct { /* ... fields ... */ } GetBlocksPayload;
typedef struct { /* ... fields ... */ } GetHeadersPayload;
typedef struct { /* ... fields ... */ } PingPayload;
typedef struct { /* ... fields ... */ } PongPayload;

// Configuration settings for the networking module.
typedef struct {
    uint16_t listen_port;
    int max_inbound;
    int max_outbound;
    uint32_t network_magic;
    const char** seed_nodes;
    size_t num_seed_nodes;
    const char* blacklist_file;
} NetworkConfig;

// --- Peer Management ---

typedef enum {
    PEER_CONNECTING,
    PEER_CONNECTED, // Handshake complete
    PEER_DISCONNECTED,
    PEER_BANNED
} PeerStatus;

typedef struct {
    SOCKET socket_fd;
    struct sockaddr_storage address; // Store full address info (IPv4/IPv6)
    char ip_address[INET6_ADDRSTRLEN]; // Max length for IPv6 string
    uint16_t port;
    PeerStatus status;
    bool is_inbound;
    uint64_t services;
    int protocol_version;
    char user_agent[256];
    int64_t connection_time;
    int64_t last_message_time;
    // Buffers for receiving/sending data would go here in a real implementation
    // uint8_t* recv_buffer;
    // size_t recv_buffer_len;
    // uint8_t* send_buffer;
    // size_t send_buffer_len;
} Peer;

// --- Global State (Simplification - use proper encapsulation in real code) ---
static Peer* g_peers[MAX_PEERS] = {0}; // Simple static array for peers
static int g_peer_count = 0;
static SOCKET g_listen_socket = INVALID_SOCKET;
static char* g_blacklist[MAX_BLACKLIST_IPS] = {0};
static int g_blacklist_count = 0;
static NetworkConfig g_config = {0};

// --- Helper Functions ---

// Simple helper to add a peer to the global list
static inline int add_peer_to_list(Peer* peer) {
    if (!peer || g_peer_count >= MAX_PEERS) {
        return -1; // List full or invalid peer
    }
    for (int i = 0; i < MAX_PEERS; ++i) {
        if (g_peers[i] == NULL) {
            g_peers[i] = peer;
            g_peer_count++;
            return i; // Return index where added
        }
    }
    return -1; // Should not happen if g_peer_count is accurate
}

// Simple helper to remove a peer from the global list
static inline void remove_peer_from_list(Peer* peer) {
    if (!peer) return;
    for (int i = 0; i < MAX_PEERS; ++i) {
        if (g_peers[i] == peer) {
            g_peers[i] = NULL;
            g_peer_count--;
            return;
        }
    }
}

// Function to set a socket to non-blocking mode
static inline bool set_socket_non_blocking(SOCKET sock) {
#ifdef _WIN32
    u_long mode = 1; // 1 to enable non-blocking socket
    return (ioctlsocket(sock, FIONBIO, &mode) == 0);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return false;
    return (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0);
#endif
}

// --- Peer Management Implementation ---

// Initiates an outbound connection to a specified peer.
// Simplified: Returns allocated Peer struct immediately, connection happens elsewhere.
static inline Peer* connect_to_peer(const char* ip, uint16_t port) {
    if (g_peer_count >= MAX_PEERS) {
        fprintf(stderr, "Cannot connect to %s:%u, max peers reached.\n", ip, port);
        return NULL;
    }
     if (is_peer_blacklisted(ip)) {
        fprintf(stderr, "Cannot connect to %s:%u, IP is blacklisted.\n", ip, port);
        return NULL;
    }

    printf("Attempting to connect to peer %s:%u...\n", ip, port);

    SOCKET sock = socket(AF_INET6, SOCK_STREAM, 0); // Try IPv6 first
    struct sockaddr_in6 addr6 = {0};
    if (sock == INVALID_SOCKET) {
        sock = socket(AF_INET, SOCK_STREAM, 0); // Fallback to IPv4
         if (sock == INVALID_SOCKET) {
            perror("socket creation failed");
            return NULL;
         }
        // Setup IPv4 address struct
        struct sockaddr_in addr4 = {0};
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &addr4.sin_addr) <= 0) {
            fprintf(stderr, "Invalid IPv4 address: %s\n", ip);
            closesocket(sock);
            return NULL;
        }
        memcpy(&addr6, &addr4, sizeof(addr4)); // Copy to storage
    } else {
        // Setup IPv6 address struct
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip, &addr6.sin6_addr) <= 0) {
            // Maybe it was IPv4? Close IPv6 socket and retry with IPv4.
            closesocket(sock);
            return connect_to_peer(ip, port); // Recursive call for IPv4 fallback
        }
    }

    // Set socket to non-blocking *before* connect for async behavior
    if (!set_socket_non_blocking(sock)) {
         perror("set_socket_non_blocking failed");
         closesocket(sock);
         return NULL;
    }

    // Attempt connection (will likely return immediately due to non-blocking)
    int connect_res = connect(sock, (struct sockaddr*)&addr6, sizeof(addr6));
    if (connect_res == SOCKET_ERROR) {
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            perror("connect failed immediately");
            closesocket(sock);
            return NULL;
        }
        // On Windows, WSAEWOULDBLOCK means connection is in progress
#else
        if (errno != EINPROGRESS) {
            perror("connect failed immediately");
            closesocket(sock);
            return NULL;
        }
         // On POSIX, EINPROGRESS means connection is in progress
#endif
    } else if (connect_res == 0) {
        // Connection succeeded immediately (less common for non-blocking)
        printf("Connected immediately to %s:%u\n", ip, port);
    }

    // If we got here, connection is either established or in progress
    Peer* peer = (Peer*)malloc(sizeof(Peer));
    if (!peer) {
        perror("malloc failed for Peer struct");
        closesocket(sock);
        return NULL;
    }
    memset(peer, 0, sizeof(Peer));
    peer->socket_fd = sock;
    memcpy(&peer->address, &addr6, sizeof(addr6));
    strncpy(peer->ip_address, ip, INET6_ADDRSTRLEN - 1);
    peer->port = port;
    peer->status = PEER_CONNECTING;
    peer->is_inbound = false;
    peer->connection_time = time(NULL);
    peer->last_message_time = peer->connection_time;

    if (add_peer_to_list(peer) < 0) {
        fprintf(stderr, "Failed to add peer %s:%u to list (list full?).\n", ip, port);
        closesocket(peer->socket_fd);
        free(peer);
        return NULL;
    }

    printf("Connection initiated for peer %s:%u (socket %d). Waiting for completion...\n", ip, port, (int)sock);
    // In a real system, an event loop (select/poll/epoll) would monitor this socket
    // for writability to confirm the connection succeeded or failed.
    // Then the VERSION message would be sent.
    return peer;
}

// Handles an incoming connection request on a listening socket.
// Simplified: Creates Peer struct, but real accept() needs event loop integration.
static inline Peer* handle_incoming_connection(SOCKET listen_socket_fd) {
    struct sockaddr_storage client_addr; // Use storage for IPv4/IPv6
    socklen_t client_addr_len = sizeof(client_addr);
    SOCKET client_socket = accept(listen_socket_fd, (struct sockaddr*)&client_addr, &client_addr_len);

    if (client_socket == INVALID_SOCKET) {
        // Might be WSAEWOULDBLOCK if listen socket is non-blocking, which is fine.
#ifdef _WIN32
        if(WSAGetLastError() != WSAEWOULDBLOCK)
           perror("accept failed");
#else
        if(errno != EWOULDBLOCK && errno != EAGAIN)
            perror("accept failed");
#endif
        return NULL; // No connection pending or error
    }

    // Get client IP and port
    char client_ip[INET6_ADDRSTRLEN];
    uint16_t client_port;
    if (client_addr.ss_family == AF_INET) {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)&client_addr;
        inet_ntop(AF_INET, &addr4->sin_addr, client_ip, sizeof(client_ip));
        client_port = ntohs(addr4->sin_port);
    } else { // AF_INET6
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&client_addr;
        inet_ntop(AF_INET6, &addr6->sin6_addr, client_ip, sizeof(client_ip));
        client_port = ntohs(addr6->sin6_port);
    }

     if (is_peer_blacklisted(client_ip)) {
        fprintf(stderr, "Rejecting connection from blacklisted IP: %s\n", client_ip);
        closesocket(client_socket);
        return NULL;
    }

    printf("Accepted connection from %s:%u (socket %d)\n", client_ip, client_port, (int)client_socket);

    // Set the new socket to non-blocking
    if (!set_socket_non_blocking(client_socket)) {
         perror("set_socket_non_blocking failed for client");
         closesocket(client_socket);
         return NULL;
    }

    Peer* peer = (Peer*)malloc(sizeof(Peer));
    if (!peer) {
        perror("malloc failed for Peer struct");
        closesocket(client_socket);
        return NULL;
    }
    memset(peer, 0, sizeof(Peer));
    peer->socket_fd = client_socket;
    memcpy(&peer->address, &client_addr, client_addr_len);
    strncpy(peer->ip_address, client_ip, INET6_ADDRSTRLEN - 1);
    peer->port = client_port;
    peer->status = PEER_CONNECTING; // Awaiting VERSION message
    peer->is_inbound = true;
    peer->connection_time = time(NULL);
    peer->last_message_time = peer->connection_time;

     if (add_peer_to_list(peer) < 0) {
        fprintf(stderr, "Failed to add incoming peer %s:%u to list (list full?).\n", client_ip, client_port);
        closesocket(peer->socket_fd);
        free(peer);
        return NULL;
    }

    // In a real system, the event loop starts monitoring this socket for readability
    // to receive the VERSION message.
    return peer;
}

// Disconnects from a specific peer and cleans up resources.
static inline void disconnect_peer(Peer* peer) {
    if (!peer) return;
    printf("Disconnecting peer %s:%u (socket %d, status %d)\n", peer->ip_address, peer->port, (int)peer->socket_fd, peer->status);
    if (peer->socket_fd != INVALID_SOCKET) {
        closesocket(peer->socket_fd);
        peer->socket_fd = INVALID_SOCKET;
    }
    peer->status = PEER_DISCONNECTED;

    // Remove from global list and free memory
    remove_peer_from_list(peer);
    free(peer); // Assuming peer was malloc'd
}

// Initiates the peer discovery process.
// Simplified: Just tries connecting to configured seed nodes.
static inline void discover_peers() {
    printf("Initiating peer discovery from %zu seeds...\n", g_config.num_seed_nodes);
    for (size_t i = 0; i < g_config.num_seed_nodes; ++i) {
        const char* seed = g_config.seed_nodes[i];
        // Basic parsing of "ip:port" - needs improvement
        char ip_buf[INET6_ADDRSTRLEN];
        uint16_t port = DEFAULT_P2P_PORT;
        const char* colon = strrchr(seed, ':');
        if (colon) {
            size_t ip_len = colon - seed;
            if (ip_len < sizeof(ip_buf)) {
                memcpy(ip_buf, seed, ip_len);
                ip_buf[ip_len] = '\0';
                port = (uint16_t)atoi(colon + 1);
            } else {
                 fprintf(stderr, "Seed IP too long: %s\n", seed);
                 continue;
            }
        } else {
             strncpy(ip_buf, seed, sizeof(ip_buf) - 1);
             ip_buf[sizeof(ip_buf) - 1] = '\0';
        }
        if (port == 0) port = DEFAULT_P2P_PORT; // Invalid port parsed

        connect_to_peer(ip_buf, port);
    }
    // In real implementation: Also query DNS seeds, send GETADDR periodically
}

// Sends a GETADDR message to a peer.
// Simplified: Uses send_message placeholder.
static inline bool send_getaddr_message(Peer* peer) {
     if (!peer || peer->status != PEER_CONNECTED) return false;
    printf("Queueing GETADDR message for peer %s:%u...\n", peer->ip_address, peer->port);
    // In a real system, payload would be NULL for GETADDR
    return send_message(peer, MSG_GET_ADDR, NULL, 0);
}

// Handles a received ADDR message.
// Simplified: Just prints received addresses.
static inline void handle_addr_message(Peer* peer, const AddrPayload* payload) {
    // AddrPayload structure needs definition and parsing logic.
    // Example: Assume AddrPayload contains a count and array of network addresses.
    // size_t count = payload->count;
    // NetworkAddress* addresses = payload->addresses;
    size_t count = 0; // Placeholder
    if (!peer || !payload) return;
    printf("Handling ADDR message from peer %s:%u with %zu addresses (Placeholder)...\n", peer->ip_address, peer->port, count);
    // In a real scenario: Iterate through addresses, add valid ones to address manager.
}

// Adds a peer's IP address to the blacklist.
static inline void add_peer_to_blacklist(const char* ip) {
    if (!ip || g_blacklist_count >= MAX_BLACKLIST_IPS) return;
    // Avoid duplicates
    for(int i = 0; i < g_blacklist_count; ++i) {
        if (g_blacklist[i] && strcmp(g_blacklist[i], ip) == 0) {
            return; // Already blacklisted
        }
    }

    g_blacklist[g_blacklist_count] = strdup(ip); // Allocate and copy IP
    if (g_blacklist[g_blacklist_count]) {
        printf("Added IP %s to blacklist.\n", ip);
        g_blacklist_count++;
        // In real implementation: Persist blacklist to file.
    } else {
        perror("strdup failed for blacklist");
    }
}

// Checks if a peer's IP address is currently blacklisted.
static inline bool is_peer_blacklisted(const char* ip) {
    if (!ip) return false;
    for (int i = 0; i < g_blacklist_count; ++i) {
        if (g_blacklist[i] && strcmp(g_blacklist[i], ip) == 0) {
            return true;
        }
    }
    return false;
}

// --- Message Handling Implementation ---

typedef enum {
    MSG_VERSION,
    MSG_VERACK,
    MSG_GET_ADDR,
    MSG_ADDR,
    MSG_INV,
    MSG_GET_DATA,
    MSG_BLOCK,
    MSG_TX,
    MSG_GET_BLOCKS,
    MSG_HEADERS,
    MSG_GET_HEADERS,
    MSG_PING,
    MSG_PONG,
    MSG_UNKNOWN
} MessageType;

typedef enum {
    INV_ERROR = 0,
    INV_TX = 1,
    INV_BLOCK = 2,
} InvType;

typedef struct {
    InvType type;
    uint8_t hash[HASH_SIZE];
} InventoryVector;

// Simplified message header (like Bitcoin)
typedef struct {
    uint32_t magic;
    char command[12];
    uint32_t length;
    uint8_t checksum[4]; // Use first 4 bytes of sha256(sha256(payload))
} MessageHeader;

// Helper to get command string from type
static inline const char* get_command_from_type(MessageType type) {
    switch(type) {
        case MSG_VERSION: return "version";
        case MSG_VERACK: return "verack";
        case MSG_GET_ADDR: return "getaddr";
        case MSG_ADDR: return "addr";
        case MSG_INV: return "inv";
        case MSG_GET_DATA: return "getdata";
        case MSG_BLOCK: return "block";
        case MSG_TX: return "tx";
        case MSG_GET_BLOCKS: return "getblocks";
        case MSG_HEADERS: return "headers";
        case MSG_GET_HEADERS: return "getheaders";
        case MSG_PING: return "ping";
        case MSG_PONG: return "pong";
        default: return "unknown";
    }
}

// Helper to get type from command string
static inline MessageType get_type_from_command(const char* command) {
    if (strncmp(command, "version", 12) == 0) return MSG_VERSION;
    if (strncmp(command, "verack", 12) == 0) return MSG_VERACK;
    if (strncmp(command, "getaddr", 12) == 0) return MSG_GET_ADDR;
    if (strncmp(command, "addr", 12) == 0) return MSG_ADDR;
    if (strncmp(command, "inv", 12) == 0) return MSG_INV;
    if (strncmp(command, "getdata", 12) == 0) return MSG_GET_DATA;
    if (strncmp(command, "block", 12) == 0) return MSG_BLOCK;
    if (strncmp(command, "tx", 12) == 0) return MSG_TX;
    if (strncmp(command, "getblocks", 12) == 0) return MSG_GET_BLOCKS;
    if (strncmp(command, "headers", 12) == 0) return MSG_HEADERS;
    if (strncmp(command, "getheaders", 12) == 0) return MSG_GET_HEADERS;
    if (strncmp(command, "ping", 12) == 0) return MSG_PING;
    if (strncmp(command, "pong", 12) == 0) return MSG_PONG;
    return MSG_UNKNOWN;
}

// Placeholder for checksum calculation (double SHA256)
static inline void calculate_checksum(const uint8_t* payload, uint32_t length, uint8_t* out_checksum) {
    // In real code: sha256(sha256(payload), hash1); memcpy(out_checksum, hash1, 4);
    memset(out_checksum, 0, 4); // Placeholder
}

// Serializes a message payload into a network-ready byte buffer.
// Simplified: Handles header, assumes payload is already serialized bytes.
static inline bool serialize_message(MessageType type, const void* payload, size_t payload_len, uint8_t** buffer, size_t* size) {
    MessageHeader header;
    header.magic = g_config.network_magic; // Use configured magic
    strncpy(header.command, get_command_from_type(type), 12);
    header.length = (uint32_t)payload_len;
    calculate_checksum((const uint8_t*)payload, header.length, header.checksum);

    *size = sizeof(MessageHeader) + payload_len;
    *buffer = (uint8_t*)malloc(*size);
    if (!*buffer) {
        perror("malloc failed for message buffer");
        return false;
    }

    memcpy(*buffer, &header, sizeof(MessageHeader));
    if (payload && payload_len > 0) {
        memcpy(*buffer + sizeof(MessageHeader), payload, payload_len);
    }

    printf("Serialized '%s' message (payload %zu bytes, total %zu bytes)\n", header.command, payload_len, *size);
    return true;
}

// Deserializes a network message from a byte buffer.
// Simplified: Reads header, returns pointer to payload within buffer.
static inline bool deserialize_message(const uint8_t* buffer, size_t size, MessageType* type, const uint8_t** payload, size_t* payload_len) {
    if (size < sizeof(MessageHeader)) {
        fprintf(stderr, "Deserialize error: buffer too small for header (%zu < %zu)\n", size, sizeof(MessageHeader));
        return false;
    }

    MessageHeader header;
    memcpy(&header, buffer, sizeof(MessageHeader));

    if (header.magic != g_config.network_magic) {
        fprintf(stderr, "Deserialize error: invalid magic number (0x%X != 0x%X)\n", header.magic, g_config.network_magic);
        return false; // Invalid magic number
    }

    size_t total_expected_size = sizeof(MessageHeader) + header.length;
    if (size < total_expected_size) {
         fprintf(stderr, "Deserialize error: incomplete message (%zu < %zu) for command '%s'\n", size, total_expected_size, header.command);
         // This indicates we need to read more data from the socket in a real async system
        return false;
    }

    *type = get_type_from_command(header.command);
    *payload_len = header.length;
    *payload = (header.length > 0) ? (buffer + sizeof(MessageHeader)) : NULL;

    // Checksum validation (placeholder)
    uint8_t calculated_checksum[4];
    calculate_checksum(*payload, *payload_len, calculated_checksum);
    if (memcmp(header.checksum, calculated_checksum, 4) != 0) {
        fprintf(stderr, "Deserialize error: checksum mismatch for command '%s'\n", header.command);
        // return false; // Don't fail on placeholder checksum
    }

    printf("Deserialized '%s' message (payload %zu bytes)\n", header.command, *payload_len);
    return true;
}

// Sends a structured message (requires payload serialization before calling).
// Assumes payload is already serialized if needed.
static inline bool send_message(Peer* peer, MessageType type, const void* payload, size_t payload_len) {
    if (!peer || peer->status == PEER_DISCONNECTED || peer->status == PEER_BANNED) return false;
    // Connection might still be in progress for outbound peers
    if (peer->status == PEER_CONNECTING && peer->is_inbound) {
         fprintf(stderr, "Cannot send message to inbound peer %s:%u before handshake complete.\n", peer->ip_address, peer->port);
         return false;
    }

    uint8_t* buffer = NULL;
    size_t size = 0;
    if (!serialize_message(type, payload, payload_len, &buffer, &size)) {
        fprintf(stderr, "Failed to serialize message type %d for peer %s:%u\n", type, peer->ip_address, peer->port);
        return false;
    }

    printf("Sending '%s' (size %zu) to peer %s:%u (socket %d)... ", get_command_from_type(type), size, peer->ip_address, peer->port, (int)peer->socket_fd);

    // Simple blocking send for this example
    // Real implementation needs non-blocking send with buffering
    ssize_t bytes_sent = send(peer->socket_fd, (const char*)buffer, (int)size, 0);
    free(buffer);

    if (bytes_sent == SOCKET_ERROR) {
#ifdef _WIN32
        int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
             printf("Send would block (WSAEWOULDBLOCK). Needs buffering.\n");
             // Handle buffering in real implementation
             return false; // Treat as failure for simplicity
        } else {
            fprintf(stderr, "\nsend failed with error: %d\n", error);
        }
#else
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            printf("Send would block (EWOULDBLOCK/EAGAIN). Needs buffering.\n");
             // Handle buffering in real implementation
             return false; // Treat as failure for simplicity
        } else {
            perror("\nsend failed");
        }
#endif
        disconnect_peer(peer);
        return false;
    }
    if ((size_t)bytes_sent != size) {
        fprintf(stderr, "\nIncomplete send to peer %s:%u (%zd/%zu bytes)\n", peer->ip_address, peer->port, bytes_sent, size);
        // Handle partial send (e.g., buffer remaining data)
        disconnect_peer(peer);
        return false; // Treat as failure for simplicity
    }

    printf("Sent %zd bytes.\n", bytes_sent);
    peer->last_message_time = time(NULL);
    return true;
}

// Processes a received raw message buffer (potentially containing multiple messages).
// Simplified: Assumes buffer contains exactly one message for now.
static inline void process_received_message(Peer* peer, const uint8_t* buffer, size_t size) {
    if (!peer || !buffer || size == 0) return;

    MessageType type = MSG_UNKNOWN;
    const uint8_t* payload = NULL;
    size_t payload_len = 0;

    printf("Processing received buffer (size %zu) from peer %s:%u...\n", size, peer->ip_address, peer->port);
    peer->last_message_time = time(NULL);

    // Try to deserialize one message from the start of the buffer
    if (deserialize_message(buffer, size, &type, &payload, &payload_len)) {
        // We successfully deserialized one message.
        // In a real system, we'd need to handle the case where the buffer
        // has more data after this message, or an incomplete message.

        // TODO: Implement actual handlers for each message type.
        // These handlers would parse the 'payload' buffer based on 'type'.
        printf("Dispatching handler for message type %d ('%s')\n", type, get_command_from_type(type));

        switch (type) {
            case MSG_VERSION:   /* handle_version_message(peer, payload, payload_len); */ break;
            case MSG_VERACK:    /* handle_verack_message(peer); */ break;
            case MSG_GET_ADDR:  send_getaddr_message(peer); break; // Simple case
            case MSG_ADDR:      /* handle_addr_message(peer, payload, payload_len); */ break;
            case MSG_INV:       /* handle_inv_message(peer, payload, payload_len); */ break;
            case MSG_GET_DATA:  /* handle_getdata_message(peer, payload, payload_len); */ break;
            case MSG_BLOCK:     /* handle_block_message(peer, payload, payload_len); */ break;
            case MSG_TX:        /* handle_tx_message(peer, payload, payload_len); */ break;
            case MSG_GET_BLOCKS:/* handle_getblocks_message(peer, payload, payload_len); */ break;
            case MSG_HEADERS:   /* handle_headers_message(peer, payload, payload_len); */ break;
            case MSG_GET_HEADERS:/* handle_getheaders_message(peer, payload, payload_len); */ break;
            case MSG_PING:      /* handle_ping_message(peer, payload, payload_len); */ break; // Send PONG
            case MSG_PONG:      /* handle_pong_message(peer, payload, payload_len); */ break;
            default:
                fprintf(stderr, "Received unknown message type %d ('%s')\n", type, get_command_from_type(type));
                 // Consider disconnecting peer for unknown commands
                 // disconnect_peer(peer);
                 // add_peer_to_blacklist(peer->ip_address);
                break;
        }
    } else {
        fprintf(stderr, "Failed to deserialize message from peer %s:%u. Disconnecting.\n", peer->ip_address, peer->port);
        disconnect_peer(peer);
        add_peer_to_blacklist(peer->ip_address);
    }
}

// --- Data Propagation & Synchronization (Gossip) ---

// Broadcasts an inventory vector to a subset of connected peers.
// Simplified: Sends to all connected peers.
static inline void gossip_inventory(const InventoryVector* inv_vector, size_t count) {
    if (!inv_vector || count == 0) return;
    printf("Gossiping %zu inventory items...\n", count);

    // In real implementation: Need to serialize the inventory vector list first.
    // size_t payload_len = serialize_inv_payload(inv_vector, count, &inv_payload_buffer);
    // For placeholder, we send nothing as payload, which is incorrect.
    const void* placeholder_payload = NULL; // Needs proper serialization
    size_t placeholder_payload_len = 0;

    int broadcast_count = 0;
    for (int i = 0; i < MAX_PEERS; ++i) {
        if (g_peers[i] && g_peers[i]->status == PEER_CONNECTED) {
            if (send_message(g_peers[i], MSG_INV, placeholder_payload, placeholder_payload_len)) {
                 broadcast_count++;
            }
        }
    }
     printf("Gossip INV sent to %d peers.\n", broadcast_count);
    // free(inv_payload_buffer) after use.
}

// Broadcasts a full transaction to peers.
// Simplified: Sends to all connected peers. Assumes tx is already serialized.
static inline void broadcast_transaction(const Transaction* tx, const uint8_t* serialized_tx, size_t tx_len) {
    if (!tx || !serialized_tx || tx_len == 0) return;
    printf("Broadcasting transaction (size %zu)...\n", tx_len);
    int broadcast_count = 0;
    for (int i = 0; i < MAX_PEERS; ++i) {
        if (g_peers[i] && g_peers[i]->status == PEER_CONNECTED) {
            // Maybe filter based on peer relay preferences later
            if (send_message(g_peers[i], MSG_TX, serialized_tx, tx_len)) {
                broadcast_count++;
            }
        }
    }
    printf("Transaction broadcast to %d peers.\n", broadcast_count);
}

// Broadcasts a full block to peers.
// Simplified: Sends to all connected peers. Assumes block is already serialized.
static inline void broadcast_block(const Block* block, const uint8_t* serialized_block, size_t block_len) {
    if (!block || !serialized_block || block_len == 0) return;
    printf("Broadcasting block %llu (size %zu)...\n", block->header.block_number, block_len);
    int broadcast_count = 0;
    for (int i = 0; i < MAX_PEERS; ++i) {
        if (g_peers[i] && g_peers[i]->status == PEER_CONNECTED) {
            if (send_message(g_peers[i], MSG_BLOCK, serialized_block, block_len)) {
                broadcast_count++;
            }
        }
    }
     printf("Block %llu broadcast to %d peers.\n", block->header.block_number, broadcast_count);
}

// Sends a GETDATA message to request specific objects from a peer.
// Simplified: Assumes inv_vector can be sent directly as payload (incorrect).
static inline bool send_getdata_message(Peer* peer, const InventoryVector* inv_vector, size_t count) {
    if (!peer || peer->status != PEER_CONNECTED || !inv_vector || count == 0) return false;
    printf("Queueing GETDATA for %zu items to peer %s:%u...\n", count, peer->ip_address, peer->port);
    // In real implementation: Need to serialize the inventory vector list.
    // size_t payload_len = serialize_inv_payload(inv_vector, count, &payload_buffer);
    const void* placeholder_payload = NULL; // Needs proper serialization
    size_t placeholder_payload_len = 0;
    bool success = send_message(peer, MSG_GET_DATA, placeholder_payload, placeholder_payload_len);
    // free(payload_buffer); after use.
    return success;
}

// Handles a received INV message.
// Simplified: Requests first unknown item via GETDATA.
static inline void handle_inv_message(Peer* peer, const uint8_t* payload, size_t payload_len) {
    if (!peer || !payload || payload_len == 0) return;
    printf("Handling INV message (payload %zu bytes) from peer %s:%u...\n", payload_len, peer->ip_address, peer->port);

    // In real implementation: Deserialize inventory vector list from payload.
    // InventoryVector* received_inv;
    // size_t count = deserialize_inv_payload(payload, payload_len, &received_inv);

    // Placeholder: Assume one item received (needs proper deserialization)
    if (payload_len >= sizeof(InventoryVector)) {
        InventoryVector* inv = (InventoryVector*)payload; // Incorrect direct cast
        size_t count = 1; // Placeholder

        printf("  Received %zu inventory items (Placeholder parsing)\n", count);

        // Check if we have the data, request if not (simplified check)
        // bool have = check_if_data_exists(inv->type, inv->hash); // Assumed function
        bool have = false; // Placeholder: assume we don't have it
        if (!have) {
             printf("  Requesting item type %d via GETDATA.\n", inv->type);
             send_getdata_message(peer, inv, 1); // Request the first unknown item
        }
        // free(received_inv); after use.
    } else {
        fprintf(stderr, "INV payload too small.\n");
    }
}

// Handles a received GETDATA message.
// Simplified: Pretends to send back requested data.
static inline void handle_getdata_message(Peer* peer, const uint8_t* payload, size_t payload_len) {
    if (!peer || !payload || payload_len == 0) return;
    printf("Handling GETDATA message (payload %zu bytes) from peer %s:%u...\n", payload_len, peer->ip_address, peer->port);

    // In real implementation: Deserialize inventory vector list from payload.
    // InventoryVector* requested_inv;
    // size_t count = deserialize_inv_payload(payload, payload_len, &requested_inv);

    // Placeholder: Assume one item requested
     if (payload_len >= sizeof(InventoryVector)) {
        InventoryVector* inv = (InventoryVector*)payload; // Incorrect direct cast
        size_t count = 1; // Placeholder
         printf("  Peer requested %zu items (Placeholder parsing)\n", count);

        // Look up data and send BLOCK or TX message
        if (inv->type == INV_BLOCK) {
            printf("  Looking up block... (Placeholder)\n");
            // Block* block = find_block_by_hash(inv->hash); // Assumed function
            // if (block) {
            //    uint8_t* serialized_block;
            //    size_t block_len = serialize_block(block, &serialized_block);
            //    send_message(peer, MSG_BLOCK, serialized_block, block_len);
            //    free(serialized_block);
            // }
        } else if (inv->type == INV_TX) {
            printf("  Looking up transaction... (Placeholder)\n");
            // Transaction* tx = find_tx_by_hash(inv->hash); // Assumed function
            // if (tx) {
            //    uint8_t* serialized_tx;
            //    size_t tx_len = serialize_transaction(tx, &serialized_tx);
            //    send_message(peer, MSG_TX, serialized_tx, tx_len);
            //    free(serialized_tx);
            // }
        }
        // free(requested_inv); after use.
    } else {
         fprintf(stderr, "GETDATA payload too small.\n");
    }
}

// Handles a received TX message.
// Simplified: Prints info.
static inline void handle_tx_message(Peer* peer, const uint8_t* payload, size_t payload_len) {
    if (!peer || !payload || payload_len == 0) return;
    printf("Handling TX message (payload %zu bytes) from peer %s:%u...\n", payload_len, peer->ip_address, peer->port);
    // In real implementation: Deserialize transaction, validate, add to mempool, maybe relay.
    // Transaction tx;
    // if (deserialize_transaction(payload, payload_len, &tx)) {
    //    if (validate_transaction(&tx) && add_to_mempool(&tx)) {
    //        InventoryVector inv = {.type = INV_TX };
    //        calculate_tx_hash(&tx, inv.hash);
    //        gossip_inventory(&inv, 1);
    //    }
    // }
}

// Handles a received BLOCK message.
// Simplified: Prints info.
static inline void handle_block_message(Peer* peer, const uint8_t* payload, size_t payload_len) {
     if (!peer || !payload || payload_len == 0) return;
    printf("Handling BLOCK message (payload %zu bytes) from peer %s:%u...\n", payload_len, peer->ip_address, peer->port);
    // In real implementation: Deserialize block, validate, add to chain, maybe relay.
    // Block block;
    // if (deserialize_block(payload, payload_len, &block)) {
    //    if (validate_block(&block) && process_block(&block)) {
    //        InventoryVector inv = {.type = INV_BLOCK };
    //        calculate_block_hash(&block, inv.hash);
    //        gossip_inventory(&inv, 1);
    //    }
    // }
}

// Sends a GETHEADERS message.
// Simplified: Payload construction omitted.
static inline bool send_getheaders_message(Peer* peer, const uint8_t (*block_locator_hashes)[HASH_SIZE], size_t locator_count, const uint8_t hash_stop[HASH_SIZE]) {
    if (!peer || peer->status != PEER_CONNECTED || !block_locator_hashes || locator_count == 0) return false;
    printf("Queueing GETHEADERS message to peer %s:%u...\n", peer->ip_address, peer->port);
    // In real implementation: Construct GetHeadersPayload (version, locator hashes, hash_stop), serialize it.
    const void* placeholder_payload = NULL; // Needs proper serialization
    size_t placeholder_payload_len = 0;
    return send_message(peer, MSG_GET_HEADERS, placeholder_payload, placeholder_payload_len);
}

// Handles a received HEADERS message.
// Simplified: Prints count.
static inline void handle_headers_message(Peer* peer, const uint8_t* payload, size_t payload_len) {
    if (!peer || !payload || payload_len == 0) return;
     // In real implementation: Deserialize list of BlockHeader structs from payload.
     // BlockHeader* headers;
     // size_t count = deserialize_headers_payload(payload, payload_len, &headers);
    size_t count = 0; // Placeholder
    printf("Handling HEADERS message (payload %zu bytes, %zu headers) from peer %s:%u...\n", payload_len, count, peer->ip_address, peer->port);
    // Process headers: validate, connect to chain, maybe request blocks via GETDATA.
    // free(headers); after use.
}


// --- Initialization & Shutdown ---

// Initializes the networking module.
static inline bool init_networking(const NetworkConfig* config) {
    if (!config) return false;
    g_config = *config; // Copy config

#ifdef _WIN32
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return false;
    }
#endif

    printf("Initializing networking module:\n");
    printf("  Port: %u\n", g_config.listen_port);
    printf("  Max Peers: %d (In: %d, Out: %d)\n", MAX_PEERS, g_config.max_inbound, g_config.max_outbound);
    printf("  Network Magic: 0x%X\n", g_config.network_magic);
    printf("  Seed Nodes: %zu\n", g_config.num_seed_nodes);
    printf("  Blacklist File: %s\n", g_config.blacklist_file ? g_config.blacklist_file : "(none)");

    // 1. Load blacklist (Simplified: assumes empty at start)
    //    In real code: open g_config.blacklist_file, read IPs into g_blacklist.

    // 2. Create listening socket
    g_listen_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    bool ipv6_only = false;
    if (g_listen_socket == INVALID_SOCKET) {
        g_listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (g_listen_socket == INVALID_SOCKET) {
             perror("Failed to create listening socket");
             shutdown_networking(); // Cleanup Winsock if needed
             return false;
        }
        printf("Listening socket created (IPv4).\n");
    } else {
        // Optional: Allow both IPv4 and IPv6 connections on the same socket
#ifdef IPV6_V6ONLY
        int no = 0;
        if (setsockopt(g_listen_socket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no)) == SOCKET_ERROR) {
            perror("setsockopt(IPV6_V6ONLY) failed");
            // Continue anyway, might just listen on IPv6
            ipv6_only = true;
             printf("Listening socket created (IPv6 only).\n");
        } else {
            printf("Listening socket created (IPv6 + IPv4 mapped).\n");
        }
#else
         printf("Listening socket created (IPv6 platform support unknown).\n");
#endif
    }

    // Bind socket
    struct sockaddr_storage bind_addr = {0};
    if (bind_addr.ss_family == AF_INET) {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)&bind_addr;
        addr4->sin_family = AF_INET;
        addr4->sin_addr.s_addr = INADDR_ANY;
        addr4->sin_port = htons(g_config.listen_port);
    } else { // AF_INET6
         struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&bind_addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_addr = in6addr_any;
        addr6->sin6_port = htons(g_config.listen_port);
    }

    if (bind(g_listen_socket, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
        perror("Failed to bind listening socket");
        closesocket(g_listen_socket); g_listen_socket = INVALID_SOCKET;
        shutdown_networking();
        return false;
    }

    // Listen
    if (listen(g_listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        perror("Failed to listen on socket");
         closesocket(g_listen_socket); g_listen_socket = INVALID_SOCKET;
        shutdown_networking();
        return false;
    }

    // Set listening socket non-blocking for use with select/poll/epoll
     if (!set_socket_non_blocking(g_listen_socket)) {
         perror("set_socket_non_blocking failed for listen socket");
         // Continue with blocking accept if needed, but non-blocking is preferred
    }

    printf("Server listening on port %u\n", g_config.listen_port);

    // 3. Initialize peer management structures (g_peers already static)
    g_peer_count = 0;

    // 4. Initialize address manager (omitted in this simplified version)

    // 5. Start connection attempts to seed nodes
    discover_peers();

    // 6. Start networking thread/event loop (CRITICAL but omitted here)
    //    This loop would use select/poll/epoll/IOCP to manage all sockets
    //    (listening socket + peer sockets) for readability/writability.
    printf("Networking initialized. (NOTE: Event loop / background thread not implemented!)\n");

    return true;
}

// Shuts down the networking module cleanly.
static inline void shutdown_networking() {
    printf("Shutting down networking module...\n");

    // 1. Close listening socket
    if (g_listen_socket != INVALID_SOCKET) {
        closesocket(g_listen_socket);
        g_listen_socket = INVALID_SOCKET;
        printf("Listening socket closed.\n");
    }

    // 2. Disconnect all connected peers
    printf("Disconnecting %d peers...\n", g_peer_count);
    // Iterate backwards as disconnect_peer modifies the list
    for (int i = MAX_PEERS - 1; i >= 0; --i) {
        if (g_peers[i]) {
            disconnect_peer(g_peers[i]); // This also frees memory and removes from list
        }
    }
    printf("All peers disconnected. %d peers remaining (should be 0).\n", g_peer_count);

    // 3. Save address manager state and blacklist (Simplified: Free blacklist memory)
    printf("Cleaning up blacklist...\n");
    for (int i = 0; i < g_blacklist_count; ++i) {
        free(g_blacklist[i]);
        g_blacklist[i] = NULL;
    }
    g_blacklist_count = 0;

    // 4. Cleanup Winsock
#ifdef _WIN32
    WSACleanup();
    printf("Winsock cleaned up.\n");
#endif
     printf("Networking shutdown complete.\n");
}


#endif // _NETWORKING_H 