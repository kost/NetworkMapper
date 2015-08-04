package org.kost.nmap.android.networkmapper;

import android.util.Log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.reflect.Field;

/**
 * Process Utility Class
 */
public class ProcessUtil {
    /* get the PID on unix systems */
    static public Integer getpid (Process process) {
        Integer pid = null;
        try {
            Field f = process.getClass().getDeclaredField("pid");
            f.setAccessible(true);
            pid = f.getInt(process);
        } catch (Throwable e) {
        }
        return pid;
    }

    static public Integer getppid (Integer pid, String shellToRun) {
        String cmdline="ps";
        String pstdout=null;
        String[] commands = { cmdline };
        Process psProcess;

        DataOutputStream outputStream;
        BufferedReader inputStream;

        Integer retPid=null;

        Log.i("NetworkMapper", "PS Finding parent of PID: " + pid);

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(shellToRun);
            processBuilder.redirectErrorStream(true);
            psProcess = processBuilder.start();

            outputStream = new DataOutputStream(psProcess.getOutputStream());
            inputStream = new BufferedReader(new InputStreamReader(psProcess.getInputStream()));

            for (String single : commands) {
                Log.i("NetworkMapper","PS Executing: "+single);
                outputStream.writeBytes(single + "\n");
                outputStream.flush();
            }
            outputStream.writeBytes("exit\n");
            outputStream.flush();
            while (((pstdout = inputStream.readLine()) != null)) {
                Log.i("NetworkMapper", "PSStdout: " + pstdout);
                String[] fields = pstdout.split("[ ]+");
                Log.i("NetworkMapper", "PSStdout: " + fields[0]+":"+fields[1]+":"+fields[2]);
                try {
                    Integer candPpid = new Integer(fields[2]);
                    Log.i("NetworkMapper", "PSStdout: " + candPpid+":"+pid);
                    if (candPpid.equals(pid)) {
                        Integer candPid = new Integer(fields[1]);
                        retPid = candPid;
                        Log.i("NetworkMapper", "PS Found: " + candPpid + ":" + candPid);
                        break;
                    }
                } catch (NumberFormatException e) {
                    // ignore
                }
            }
            psProcess.waitFor();
            psProcess.destroy();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        return retPid;
    }

    public static boolean canRunRootCommands()
    {
        boolean retval;
        Process suProcess;
        try
        {
            suProcess = Runtime.getRuntime().exec("su");
            BufferedWriter os = new BufferedWriter(new OutputStreamWriter(suProcess.getOutputStream()));
            BufferedReader osRes = new BufferedReader(new InputStreamReader(suProcess.getInputStream()));
            os.write("id\n");
            os.flush();
            String currUid = osRes.readLine();
            boolean exitSu;
            if (null == currUid)
            {
                retval = false;
                exitSu = false;
            }
            else if (currUid.contains("uid=0"))
            {
                retval = true;
                exitSu = true;
            }
            else
            {
                retval = false;
                exitSu = true;
            }

            if (exitSu)
            {
                os.write("exit\n");
                os.flush();
            }
        }
        catch (Exception e)
        {
            retval = false;
        }
        return retval;
    }
}
