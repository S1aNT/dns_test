#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>

#define ADDRESS	0x00

bool SendRawPackets(const char InterfaceName[],
                    const uint64_t & NumberOfPacketStrings,
                    const unsigned int & PacketLength,
                    const std::vector<std::string> & VectorOfPacketStrings)  {

    struct sockaddr_ll SocketAddress;

    struct ifreq InterfaceIndex;
    struct ifreq InterfaceMac;

    int Socket = -1;
    if ((Socket = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        std::cerr << "[ERROR] Can not create raw socket." << std::endl;
        return false;
    }

    memset(&InterfaceIndex, 0, sizeof(struct ifreq));
    strncpy(InterfaceIndex.ifr_name, InterfaceName, IFNAMSIZ-1);
    if (ioctl(Socket, SIOCGIFINDEX, &InterfaceIndex) < 0) {
        std::cerr << "[ERROR] Can not get netiface index." << std::endl;
        return false;
    }

    memset(&InterfaceMac, 0, sizeof(struct ifreq));
    strncpy(InterfaceMac.ifr_name, InterfaceName, IFNAMSIZ-1);
    if (ioctl(Socket, SIOCGIFHWADDR, &InterfaceMac) < 0) {
        std::cerr << "[ERROR] Can not get HW addr for netiface." << std::endl;
        return false;
    }

    SocketAddress.sll_ifindex = InterfaceIndex.ifr_ifindex;
    SocketAddress.sll_halen = ETH_ALEN;
    for (int IndexOfAddress = 0; IndexOfAddress < 8; ++IndexOfAddress) {
        SocketAddress.sll_addr[IndexOfAddress] = ADDRESS;
    }

    for (int IndexOfPacketString = 0; IndexOfPacketString < NumberOfPacketStrings; ++IndexOfPacketString) {
        if (sendto(Socket, VectorOfPacketStrings[IndexOfPacketString].c_str(), PacketLength, 0, (struct sockaddr*)&SocketAddress, sizeof(struct sockaddr_ll)) < 0) {
            std::cerr << "[ERROR] Can not send packet." << std::endl;
            return false;
        }
    }

    return true;
}

int main(int argc, char *argv[]) {

    char InterfaceName[IFNAMSIZ];
    std::string FileNameWithPackets = "packets.txt";
    unsigned int PacketLength = 0;
    uint64_t NumberOfPacketStrings = 0;

    if (argc == 5) {
        std::istringstream InterfaceNameStream(argv[1]);
        if (!(InterfaceNameStream >> InterfaceName)) {
            std::cerr << "[ERROR] First argument is network interface name." << std::endl;
            exit(1);
        }

        std::istringstream FileNameWithPacketsStream(argv[2]);
        if (!(FileNameWithPacketsStream >> FileNameWithPackets)) {
            std::cerr << "[ERROR] Second argument is file name with raw packets." << std::endl;
            exit(1);
        }

        std::istringstream PacketLengthStream(argv[3]);
        if (!(PacketLengthStream >> PacketLength)) {
            std::cerr << "[ERROR] Third argument is packet length." << std::endl;
            exit(1);
        }

        std::istringstream NumberOfPacketStringStream(argv[4]);
        if (!(NumberOfPacketStringStream >> NumberOfPacketStrings)) {
            std::cerr << "[ERROR] Fourth argument is number of packets." << std::endl;
            exit(1);
        }
    } else {
        std::cout << "[INFO] Usage: " << argv[0] << " \"<iface>\" \"<filename_with_raw_packets>\" "
                  << " <packet_len> <number_of_packets>" << std::endl;
    }

    std::vector<std::string> VectorOfPacketStrings;

    try {
        std::ifstream Packets(FileNameWithPackets, std::ios::in | std::ios::binary);

        for (int IndexOfPacketsLine = 0; IndexOfPacketsLine < NumberOfPacketStrings; ++IndexOfPacketsLine) {
            std::string PacketString = std::string(PacketLength, ' ');
            for (int IndexOfByteInPacket = 0; IndexOfByteInPacket < PacketLength; ++IndexOfByteInPacket) {
                PacketString[IndexOfByteInPacket] = (char) Packets.get();
            }
            VectorOfPacketStrings.push_back(PacketString);
        }

        SendRawPackets(InterfaceName, NumberOfPacketStrings, PacketLength, VectorOfPacketStrings);
    } catch (const std::exception &Exc) {
        std::cerr << "[ERROR] Exception: " << Exc.what() << std::endl;
        exit(1);
    }
    return 0;
}