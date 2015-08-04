package org.kost.nmap.android.networkmapper;

/**
 * Sanitizing Utility Class
 */
public class SanitUtil {

    static public String PoorManFilter(String str) {
        return str.replaceAll("[^A-Za-z0-9_ .:/-]","");
    }
}
