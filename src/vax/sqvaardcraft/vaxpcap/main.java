package vax.sqvaardcraft.vaxpcap;

import org.jnetpcap.Pcap;

/**

 @author toor
 */
public class main {
  static public void main( String[] args ) {
    System.setProperty( "java.library.path",
            System.getProperty( "java.library.path" ) + ";" + System.getProperty( "user.dir" ) );
    VaxPcap vpc = new VaxPcap( VaxPcap.findActiveNIC(), Pcap.DEFAULT_SNAPLEN, Pcap.MODE_NON_PROMISCUOUS, Pcap.DEFAULT_TIMEOUT );
    vpc.sniff( 100000 );
  }
}
