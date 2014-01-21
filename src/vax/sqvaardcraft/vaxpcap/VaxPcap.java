package vax.sqvaardcraft.vaxpcap;

import java.util.ArrayList;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import static org.jnetpcap.Pcap.*;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;

/**

 @author toor
 */
public class VaxPcap {
  protected Pcap pc;

  public VaxPcap() {
    this( findActiveNIC() );
  }

  public VaxPcap( PcapIf pi ) {
    this( pi, DEFAULT_SNAPLEN, DEFAULT_PROMISC, DEFAULT_TIMEOUT );

  }

  public VaxPcap( PcapIf pi, int snaplen, int promisc, int timeout ) {
    StringBuilder errbuf = new StringBuilder();
    pc = Pcap.openLive( pi.getName(), snaplen, promisc, timeout, errbuf );
    if ( pc == null )
      throw new VaxPcapException( errbuf );
  }

  public void sniff( int packet_amount ) {
    //final String MIME_to_intercept = "video/x-flv";
    final String[] magic_to_intercept = { "flv", "mp4" };
    //final Tcp tcp = new Tcp();
    //final Udp udp = new Udp();
    final Ip4 ip4 = new Ip4();
    final Http http = new Http();

    pc.loop( packet_amount, (JPacket packet, Void user) -> {
      if ( packet.hasHeader( http )
              && http.hasField( Http.Request.RequestMethod ) && http.fieldValue( Http.Request.RequestMethod ).equals( "GET" ) ) {
        String host = http.fieldValue( Http.Request.Host );
        if ( host == null )
          return;
        for( String s : magic_to_intercept )
          if ( http.fieldValue( Http.Request.RequestUrl ).contains( s ) ) {
            System.out.println( "http://" + host + http.fieldValue( Http.Request.RequestUrl ) );
            return;
          }
      }
    }, null );
  }

  static public String IPv4_toString( byte[] bs ) {
    return ( bs[0] & 0xFF ) + "." + ( bs[1] & 0xFF ) + "." + ( bs[2] & 0xFF ) + "." + ( bs[3] & 0xFF );
  }

  static public PcapIf findActiveNIC() {
    for( PcapIf pi : findAllDevs() )
      if ( !pi.getAddresses().isEmpty() )
        return pi;
    throw new VaxPcapException( "no active NIC found" );
  }

  static public ArrayList<PcapIf> findAllDevs() {
    StringBuilder errbuf = new StringBuilder();
    ArrayList<PcapIf> nic_list = new ArrayList<>();
    if ( Pcap.findAllDevs( nic_list, errbuf ) == -1 )
      throw new VaxPcapException( errbuf );
    return nic_list;
  }
}
