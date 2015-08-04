package org.kost.nmap.android.networkmapper;

import android.content.SharedPreferences;

/**
 * Created by vkosturj on 04/08/15.
 */
public class NmapBinUtil {
    static public String determineNmapBinLocation (SharedPreferences sharedPrefs, String defloc, String appdir) {
        String nmapbin;
        String binarydir=sharedPrefs.getString("pref_binaryloc",defloc);

        String bindir;
        if (binarydir.length()>0) {
            bindir =binarydir;
        } else {
            bindir = appdir + "/bin";
        }
        nmapbin = bindir +"/nmap";
        return (nmapbin);
    }
}
