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
#define PACKET_LEN 80

bool SendRawPackets(char InterfaceName[],
                    uint64_t & NumberOfPacketStrings,
                    uint64_t & PacketLength,
                    std::vector<std::string> & VectorOfPacketStrings)
{
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

    const char * PacketString;

    for (int IndexOfPacketString = 0; IndexOfPacketString < NumberOfPacketStrings; ++IndexOfPacketString) {
        PacketString = VectorOfPacketStrings[IndexOfPacketString].c_str();
        if (sendto(Socket, PacketString, PacketLength, 0, (struct sockaddr*)&SocketAddress, sizeof(struct sockaddr_ll)) < 0) {
            std::cerr << "[ERROR] Can not send packet." << std::endl;
            return false;
        }
    }

    return true;
}

int main(int argc, char *argv[]) {
    uint64_t NumberOfPacketStrings = 0;
    uint64_t PacketLength = PACKET_LEN;
    char InterfaceName[IFNAMSIZ];

    if (argc >= 3) {
        std::istringstream InterfaceNameStream(argv[1]);
        if (!(InterfaceNameStream >> InterfaceName)) {
            std::cerr << "[ERROR] First argument is network interface name." << std::endl;
            exit(1);
        }

        std::istringstream NumberOfPacketStringStream(argv[2]);
        if (!(NumberOfPacketStringStream >> NumberOfPacketStrings)) {
            std::cerr << "[ERROR] Second argument is number of packets." << std::endl;
            exit(1);
        }
    }

    std::string FileNameWithPackets = "packets.txt";
    std::vector<std::string> VectorOfPacketStrings;

    try {
        std::ifstream Packets(FileNameWithPackets, std::ios::in | std::ios::binary);

        for (int IndexOfPacketsLine = 0; IndexOfPacketsLine < NumberOfPacketStrings; ++IndexOfPacketsLine) {
            char PacketString[PacketLength];

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

}