# Stateless Network Sniffer (V1)

A lightweight, dependency-free network packet sniffer written in Python. This tool captures and parses raw Ethernet frames directly from the host network interface to extract IPv4, TCP, UDP, and ICMP header information.

## Architecture

This script bypasses high-level socket wrappers and interacts directly with the Data Link layer (`AF_PACKET`, `SOCK_RAW`). It manually unpacks byte structures using Python's `struct` module to resolve:
- Dynamic IP Header Lengths (IHL)
- Source/Destination IP Addresses
- Transport Layer Protocols and Ports

## Deployment

This tool is containerized for isolated execution. Due to the nature of raw sockets and network layer access, the container requires specific network capabilities and host network binding.

### Prerequisites
- Docker
- Linux-based host OS

### Build
\`\`\`bash
docker build -t net-sniffer:v1 .
\`\`\`

### Run
To successfully capture host traffic, the container must be run with the `--network host` flag and elevated networking capabilities:

\`\`\`bash
docker run --network host --cap-add=NET_RAW --cap-add=NET_ADMIN -it net-sniffer:v1
\`\`\`
