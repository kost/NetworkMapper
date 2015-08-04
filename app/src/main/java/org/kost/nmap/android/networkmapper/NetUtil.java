package org.kost.nmap.android.networkmapper;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

/**
 * Net Utility Class
 */
public class NetUtil {
    static public String getIPs() {
        String interfaces="";
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements();) {
                NetworkInterface intf = en.nextElement();
                for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements();) {
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress()) {
                        interfaces=interfaces+"[IP]: "+ inetAddress.getHostAddress() +"\n";
                    }
                }
            }
        } catch (SocketException ignored) {
        }
        return interfaces;
    }

}
