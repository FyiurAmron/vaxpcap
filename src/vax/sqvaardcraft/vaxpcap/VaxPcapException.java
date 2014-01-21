package vax.sqvaardcraft.vaxpcap;

public class VaxPcapException extends RuntimeException {
  protected VaxPcapException( String message ) {
    super( message );
  }

  protected VaxPcapException( StringBuilder sb ) {
    super( sb.toString() );
  }
}
