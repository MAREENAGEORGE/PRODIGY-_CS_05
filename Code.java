import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;

public class PacketAnalyzer {
    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        PcapNetworkInterface device = Pcaps.findAllDevs().get(0);
        PcapHandle handle = device.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        handle.loop(10, packet -> {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            if (ipV4Packet != null) {
                System.out.println(ipV4Packet.getHeader().getSrcAddr() + " -> " +
                                   ipV4Packet.getHeader().getDstAddr() +
                                   " | Protocol: " + ipV4Packet.getHeader().getProtocol());
            }
        });
        handle.close();
    }
}
