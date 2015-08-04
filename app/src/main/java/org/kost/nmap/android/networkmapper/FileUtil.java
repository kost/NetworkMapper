package org.kost.nmap.android.networkmapper;

import java.io.File;

/**
 * File/Dir Utility Class
 */
public class FileUtil {
    static public void makedir (String dir) {
        File myDir = new File(dir);

        if(!myDir.isDirectory()) {
            myDir.mkdirs();
        }
    }

    static void DeleteRecursive(File fileOrDirectory) {
        if (fileOrDirectory.isDirectory())
            for (File child : fileOrDirectory.listFiles())
                DeleteRecursive(child);

        fileOrDirectory.delete();
    }
}
