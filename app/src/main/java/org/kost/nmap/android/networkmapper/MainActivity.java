package org.kost.nmap.android.networkmapper;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Environment;
import android.os.PowerManager;
import android.preference.PreferenceManager;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;


public class MainActivity extends ActionBarActivity {
    private ProgressDialog sharedProgressDialog;
    private ProgressDialog cancelDialog;
    private String nmapurl;

    private int currentEabi;
    private TextView outputView;
    private EditText editText;
    private ScrollView scrollView;
    private Spinner spinner;
    private Button scanButton;

    private SharedPreferences sharedPrefs;

    private String nmapbin;
    private String shellToRun;

    private boolean startedScan;
    private ExecuteTask executeTask;

    Process scanProcess;

    private String archs;
    private boolean doneFallback;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // supportRequestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

        startedScan=false;
        sharedPrefs = PreferenceManager.getDefaultSharedPreferences(this);

        setContentView(R.layout.activity_main);

        // ProgressDialog
        sharedProgressDialog = new ProgressDialog(this);
        sharedProgressDialog.setMessage(getString(R.string.dlg_progress_title_download));
        sharedProgressDialog.setIndeterminate(true);
        sharedProgressDialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
        sharedProgressDialog.setCancelable(true);

        cancelDialog = new ProgressDialog(this);
        cancelDialog.setMessage(getString(R.string.dlg_progress_cancel));
        cancelDialog.setIndeterminate(false);
        cancelDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
        cancelDialog.setCancelable(false);

        outputView=(TextView)findViewById(R.id.outputView);
        editText=(EditText)findViewById(R.id.editText);
        scrollView=(ScrollView)findViewById(R.id.scrollView);
        spinner=(Spinner)findViewById(R.id.spinner);
        scanButton=(Button)findViewById(R.id.scanButton);

        // setSupportProgressBarIndeterminateVisibility(true);

        determineNmapBinLocation();
        shellToRun="sh";
        Log.i("NetworkMapper","shell: "+shellToRun+" nmapbin: "+nmapbin);

        if (savedInstanceState != null) {
            Log.i("NetworkMapper","RestoreState()");
            outputView.setText(savedInstanceState.getString("outputView"));
        } else {
            outputView.setText("");
            displaySuInfo();
        }
        if (!isBinaryHere(false)) {
            askToDownload();
        }
    }

    private void determineNmapBinLocation () {
        String binarydir=sharedPrefs.getString("pref_binaryloc",getString(R.string.pref_default_binaryloc));

        String appdir = getFilesDir().getParent();
        String bindir;
        if (binarydir.length()>0) {
            bindir =binarydir;
        } else {
            bindir = appdir + "/bin";
        }
        nmapbin = bindir +"/nmap";
    }

    private void askToDownload() {
        DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                if (which == DialogInterface.BUTTON_POSITIVE) {
                        downloadAll();
                }
            }
        };

        AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
        builder.setMessage(getString(R.string.dlg_ask2download))
                .setPositiveButton(getString(R.string.dlg_ask2download_yes), dialogClickListener)
                .setNegativeButton(getString(R.string.dlg_ask2download_no), dialogClickListener)
                .show();
    }

    private void displaySuInfo() {
        if (canRunRootCommands()) {
            outputView.append(getString(R.string.info_gotroot));
            shellToRun="su";
        } else {
            outputView.append(getString(R.string.info_noroot));
        }
    }

    private String PoorManFilter(String str) {
        return str.replaceAll("[^A-Za-z0-9_ .:/-]","");
    }

    private String getIPs() {
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

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public void onSaveInstanceState(Bundle savedInstanceState) {
        savedInstanceState.putString("outputView",outputView.getText().toString());

        // Always call the superclass so it can save the view hierarchy state
        super.onSaveInstanceState(savedInstanceState);
    }

    /* get the PID on unix systems */
    public Integer getpid (Process process) {
        Integer pid = null;
            try {
                Field f = process.getClass().getDeclaredField("pid");
                f.setAccessible(true);
                pid = f.getInt(process);
            } catch (Throwable e) {
            }
        return pid;
    }

    public Integer getppid (Integer pid) {
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

    public void cancelScan () {
        Log.i("NetworkMapper","Started Canceling scan!");
        cancelDialog.show();
        // Toast.makeText(getApplicationContext(),getString(R.string.toast_scan_canceling), Toast.LENGTH_SHORT).show();
        executeTask.cancel(true);
        Thread cancelThread = new Thread() {
            @Override
            public void run() {
                try {
                    String killstr = new String("/system/bin/kill -9 "+ getppid(getpid(scanProcess)));
                    Log.i("NetworkMapper","Executing kill: "+killstr);
                    Runtime.getRuntime().exec(killstr);
                } catch (IOException e) {
                    Log.e("NetworkMapper", "Error killing process");
                }
            }
        };
        Log.i("NetworkMapper","Starting canceling thread.");
        cancelThread.start();
    }

    public void onScanButtonClick (View v) {
        StringBuilder sbcmdline = new StringBuilder("");

        String profileopt;

        if (startedScan) {
            cancelScan();
            return;
        }

        determineNmapBinLocation();

        // Spinner options - TODO: check if array is large enough
        String scanSwitches[]=getResources().getStringArray(R.array.scan_values_array);
        profileopt=" "+scanSwitches[spinner.getSelectedItemPosition()]+" ";

        // get defaultopts;
        String defaultopts=sharedPrefs.getString("pref_defaultopts", getString(R.string.pref_default_defaultopts));

        sbcmdline.append(PoorManFilter(nmapbin));
        // add defaultopts if there any
        if (defaultopts.length()>0) {
            sbcmdline.append(" ");
            sbcmdline.append(PoorManFilter(defaultopts));
            sbcmdline.append(" ");
        }
        // add profile options
        sbcmdline.append(profileopt);
        sbcmdline.append(" ");
        // add target and any options from editText
        sbcmdline.append(PoorManFilter(editText.getText().toString()));
        String cmdline = sbcmdline.toString();
        Log.i("NetworkMapper", "Executing: " + cmdline);
        outputView.append(getString(R.string.info_executing) + cmdline + "\n");

        scanButton.setText(getString(R.string.scanbutton_stop));
        startedScan=true;

        executeTask = new ExecuteTask(this);
        executeTask.execute(cmdline);

        sharedProgressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialog) {
                executeTask.cancel(true);
            }
        });

    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        switch (id) {
            case R.id.action_settings:
                Intent i = new Intent(getApplicationContext(), SettingsActivity.class);
                startActivityForResult(i, 1);
                break;

            case R.id.action_download:
                downloadAll();
                break;

            case R.id.action_clear:
                outputView.setText("");
                break;

            case R.id.action_share:
                Intent sendIntent = new Intent();
                sendIntent.setAction(Intent.ACTION_SEND);
                sendIntent.putExtra(Intent.EXTRA_TEXT, outputView.getText());
                sendIntent.setType("text/plain");
                startActivity(Intent.createChooser(sendIntent, getText(R.string.share_to)));
                break;

            case R.id.action_displayip:
                outputView.append(getIPs());
                break;

            case R.id.action_about:
                AlertDialog.Builder aboutbuilder = new AlertDialog.Builder(this);
                AlertDialog aboutdlg = aboutbuilder.setTitle(getString(R.string.aboutdlg_title)).
                    setMessage(getString(R.string.aboutdlg_text)).create();
                aboutdlg.show();
                break;
        }
        return super.onOptionsItemSelected(item);
    }

    private static boolean canRunRootCommands()
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

    private boolean isBinaryHere(boolean displayOutput) {
        File nmapfile = new File(nmapbin);
        if (nmapfile.canExecute()) {
            if (displayOutput) {
                outputView.append(getString(R.string.info_binary_ok));
            }
            return true;
        } else {
            if (displayOutput) {
                outputView.append(getString(R.string.info_binary_notok));
            }
            return false;
        }
    }

    private void scrollToBottom()
    {
        scrollView.post(new Runnable()
        {
            public void run()
            {
                scrollView.smoothScrollTo(0, outputView.getBottom());
            }
        });
    }

    private class ExecuteTask extends AsyncTask<String,String,String> {
        final Context context;
        PowerManager.WakeLock mWakeLock;

        @Override
        protected String doInBackground(String... sParm) {
            String cmdline=sParm[0];
            String pstdout=null;
            StringBuilder wholeoutput = new StringBuilder("");
            String[] commands = { cmdline };

            DataOutputStream outputStream;
            BufferedReader inputStream;

//            Process scanProcess;

            try {
                ProcessBuilder processBuilder = new ProcessBuilder(shellToRun);
                processBuilder.redirectErrorStream(true);
                scanProcess = processBuilder.start();

                outputStream = new DataOutputStream(scanProcess.getOutputStream());
                inputStream = new BufferedReader(new InputStreamReader(scanProcess.getInputStream()));

                for (String single : commands) {
                    Log.i("NetworkMapper","Single Executing: "+single);
                    outputStream.writeBytes(single + "\n");
                    outputStream.flush();
                }
                outputStream.writeBytes("exit\n");
                outputStream.flush();
                while (((pstdout = inputStream.readLine()) != null)) {
                    if (isCancelled()) {
                        scanProcess.destroy();
                        break;
                    } else {
                        if (pstdout != null) {
                            pstdout = pstdout + "\n";
                            wholeoutput.append(pstdout);
                        }
                        Log.i("NetworkMapper", "Stdout: " + pstdout);
                        publishProgress(pstdout, null);
                        pstdout = null;
                    }
                }

                if (!isCancelled()) scanProcess.waitFor();
            } catch (IOException | InterruptedException e) {
                throw new RuntimeException(e);
            }

            return wholeoutput.toString();
        }

        @Override
        protected void onPreExecute() {
            // super.onPreExecute();
            // take CPU lock to prevent CPU from going off if the user
            // presses the power button during download
            PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
            mWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,
                    getClass().getName());
            mWakeLock.acquire();

            Toast.makeText(context,getString(R.string.toast_scan_started), Toast.LENGTH_SHORT).show();
        }

        @Override
        protected void onProgressUpdate(String... progress) {
            // super.onProgressUpdate(progress);
            if (progress[0]!=null) outputView.append(progress[0]);
            if (progress[1]!=null) outputView.append(progress[1]);
            scrollToBottom();
        }

        public ExecuteTask(Context context) {
            this.context = context;
        }

        protected void cleanupOnEnd () {
            mWakeLock.release();
            setSupportProgressBarIndeterminateVisibility(false);
            startedScan=false;
            scanButton.setText(getString(R.string.scanbtn));
            scrollToBottom();
        }

        @Override
        protected void onCancelled () {
            cleanupOnEnd();
            cancelDialog.dismiss();
            Toast.makeText(context,getString(R.string.toast_scan_canceled), Toast.LENGTH_SHORT).show();
        }

        @Override
        protected void onPostExecute(String result) {
            cleanupOnEnd();
            // For future: add scan to history scans
            // if (result!=null) outputView.append(result);
            Toast.makeText(context,getString(R.string.toast_scan_finished), Toast.LENGTH_SHORT).show();
        }

    }

    private class DownloadTask extends AsyncTask<String,Integer,String> {
        final Context context;
        PowerManager.WakeLock mWakeLock;
        String dlurl;
        String dlfn;
        String dlprefix;

        @Override
        protected String doInBackground(String... sParm) {
            InputStream input = null;
            OutputStream output = null;
            HttpURLConnection connection = null;
            try {
                dlurl=sParm[0];
                dlfn=sParm[1];
                dlprefix=sParm[2];
                URL url = new URL(sParm[0]);
                Log.i("NetworkMapper","Downloading URL: "+url.toString());
                connection = (HttpURLConnection) url.openConnection();
                connection.connect();

                // expect HTTP 200 OK, so we don't mistakenly save error report
                // instead of the file
                if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                    return "Server returned HTTP " + connection.getResponseCode()
                            + " " + connection.getResponseMessage();
                }

                // this will be useful to display download percentage
                // might be -1: server did not report the length
                int fileLength = connection.getContentLength();

                // download the file
                input = connection.getInputStream();
                // output = new FileOutputStream("/sdcard/file_name.extension");
                Log.i("NetworkMapper","Downloading to: "+sParm[1]);
                output = new FileOutputStream(sParm[1]);


                byte data[] = new byte[4096];
                long total = 0;
                int count;
                while ((count = input.read(data)) != -1) {
                    // allow canceling with back button
                    if (isCancelled()) {
                        input.close();
                        return null;
                    }
                    total += count;
                    // publishing the progress....
                    if (fileLength > 0) // only if total length is known
                        this.publishProgress((int) (total * 100 / fileLength));
                    output.write(data, 0, count);
                }
            } catch (Exception e) {
                return e.toString();
            } finally {
                try {
                    if (output != null)
                        output.close();
                    if (input != null)
                        input.close();
                } catch (IOException ignored) {
                }

                if (connection != null)
                    connection.disconnect();
            }
            return null;
        }

        @Override
        protected void onPreExecute() {
            // super.onPreExecute();
            // take CPU lock to prevent CPU from going off if the user
            // presses the power button during download
            PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
            mWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,
                    getClass().getName());
            mWakeLock.acquire();
            sharedProgressDialog.show();
        }

        @Override
        protected void onProgressUpdate(Integer... progress) {
            // super.onProgressUpdate(progress);
            // if we get here, length is known, now set indeterminate to false
            sharedProgressDialog.setIndeterminate(false);
            sharedProgressDialog.setMax(100);
            sharedProgressDialog.setProgress(progress[0]);
            sharedProgressDialog.setMessage(getString(R.string.dlg_progress_title_download));
        }

        public DownloadTask(Context context) {
            this.context = context;
        }

    }

    private class UnzipTask extends AsyncTask<String,Integer,String> {
        private final Context context;
        private PowerManager.WakeLock mWakeLock;
        int per;
        String dlprefix;
        int maxfiles;

        public UnzipTask(Context context) {
            this.context = context;
        }

        @Override
        protected String doInBackground(String... sParm) {
            String zipfn=sParm[0];
            String dest=sParm[1];
            dlprefix=sParm[2];
            per=0;
            maxfiles=10;
            try {
                // set maximum to number of compress files
                ZipFile zip = new ZipFile(zipfn);
                maxfiles=zip.size();
                sharedProgressDialog.setMax(maxfiles);

                FileInputStream fin = new FileInputStream(zipfn);
                ZipInputStream zin = new ZipInputStream(fin);
                ZipEntry ze;
                while ((ze = zin.getNextEntry()) != null) {
                    Log.v("NetworkMapper", "Unzipping " + ze.getName());

                    if (ze.isDirectory()) {
                        makedir(dest + ze.getName());
                    } else {
                        per++;
                        publishProgress(per);

                        int size;
                        byte[] buffer = new byte[2048];

                        FileOutputStream outStream = new FileOutputStream(dest+ze.getName());
                        BufferedOutputStream bufferOut = new BufferedOutputStream(outStream, buffer.length);

                        while((size = zin.read(buffer, 0, buffer.length)) != -1) {
                            bufferOut.write(buffer, 0, size);
                        }

                        bufferOut.flush();
                        bufferOut.close();
                    }

                }
                zin.close();
                new File(zipfn).delete(); // delete file after successful unzip
            } catch (Exception e) {
                Log.e("NetworkMapper", "unzip", e);
            }
            return dest;
        }

        @Override
        protected void onPreExecute() {
            // super.onPreExecute();
            sharedProgressDialog.setMessage(getString(R.string.dlg_progress_title_extraction));
            sharedProgressDialog.show();
        }

        protected void onProgressUpdate(Integer... progress) {
            sharedProgressDialog.setMax(maxfiles);
            sharedProgressDialog.setProgress(per);
        }

    }

    private class SimpleHttpTask extends AsyncTask<String, Void, String> {
        private final Context context;
        private PowerManager.WakeLock mWakeLock;

        public SimpleHttpTask(Context context) {
            this.context = context;
        }

        @Override
        protected String doInBackground(String... params) {
            String urllink = params[0];

            String str;

            Integer count = 0;
            Integer maxTries = 3;
            while(true) {
                URL url;
                try {
                    url = new URL(urllink);
                    Log.i("NetworkMapper", "Downloading from URL: " + url.toString() + "\n");
                    HttpURLConnection httpurlconn = (HttpURLConnection) url.openConnection();
                    httpurlconn.setInstanceFollowRedirects(true);
                    httpurlconn.connect();

                    InputStream in = new BufferedInputStream(httpurlconn.getInputStream());
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(in));

                    str = bufferedReader.readLine();
                    in.close();
                    httpurlconn.disconnect();
                    Log.i("NetworkMapper", "Downloaded " + str);
                    return str;
                } catch (MalformedURLException e) {
                    // throw new RuntimeException(e);
                    Log.e("NetworkMapper", "MalformedURL: " + urllink);
                    return null;
                } catch (IOException e) {
                    // throw new RuntimeException(e);
                    Log.e("NetworkMapper", "IOException: " + urllink);
                    //outputView.append(getString(R.string.output_error_download_ioexception)+count.toString()+"\n");
                    if (++count == maxTries) {
                        Log.e("NetworkMapper", "Reached maximum tries");
                        return null;
                    }
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e1) {
                        Log.e("NetworkMapper","ThreadSleep");
                    }
                }
            }
        }

        @Override
        protected void onPreExecute() {
            // super.onPreExecute();
            // take CPU lock to prevent CPU from going off if the user
            // presses the power button during download
            PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
            mWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,
                    getClass().getName());
            mWakeLock.acquire();
            outputView.append(getString(R.string.output_downloading_version_file));
            sharedProgressDialog.show();
        }

        @Override
        protected void onPostExecute(String result) {
            mWakeLock.release();
            sharedProgressDialog.dismiss();
            if (result == null) {
                // XXX reporting with null doesn't make sense
                outputView.append(getString(R.string.toast_download_version_error)+"\n");
                // Toast.makeText(context, getString(R.string.toast_download_version_error) + result, Toast.LENGTH_LONG).show();
                return;
            }

            outputView.append(getString(R.string.toast_download_version_ok) + "\n");
            //Toast.makeText(context,getString(R.string.toast_download_version_ok), Toast.LENGTH_SHORT).show();

            doneFallback=false;
            archs=donexteabi();
            downloadBinary(result,archs);
        }

    }

    private void downloadAll () {
        currentEabi = 0;
        nmapurl=sharedPrefs.getString("pref_updateurl",getString(R.string.pref_default_updateurl));
        final SimpleHttpTask verTask = new SimpleHttpTask(this);
        String versionurl = nmapurl + "/nmap-latest.txt";
        outputView.append("Downloading from: "+versionurl+"\n");
        verTask.execute(versionurl);

        sharedProgressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialog) {
                verTask.cancel(true);
            }
        });
    }

    private String donexteabi() {
        switch (currentEabi++) {
            case 0:
                return Build.CPU_ABI;
            case 1:
                return Build.CPU_ABI2;
        }
        return null;
    }

    private void downloadBinary(final String prefixfn, String eabi) {
        String appdir = getFilesDir().getParent();
        String bindir = appdir + "/bin";
        String dldir = appdir + "/dl";
        String root = Environment.getExternalStorageDirectory().toString();
        final String datadldir = root + "/opt";

        Log.i("NetworkMapper", "Using bindir:" + bindir + ", dldir:" + dldir);
        makedir(bindir);
        makedir(dldir);

        String binaryfn=prefixfn+"-binaries-"+eabi+".zip";

        Log.i("NetworkMapper","Using binaryfn: "+binaryfn);
        outputView.append(getString(R.string.output_using_binary_filename)+binaryfn+".\n");

        final DownloadTask binaryTask = new DownloadTask(this) {
            @Override
            protected void onPostExecute(String result) {
                sharedProgressDialog.dismiss();
                if (result != null) {
                    mWakeLock.release();
                    String nextEabi = donexteabi();
                    archs = archs+":"+nextEabi;
                    if (nextEabi==null) {
                        if (doneFallback) {
                            // Toast.makeText(context, getString(R.string.toast_dowload_binary_error) + result, Toast.LENGTH_LONG).show();
                            outputView.append(getString(R.string.output_no_more_architectures_to_try) + ": " + result + ": "+archs+"\n");
                        } else {
                            outputView.append(getString(R.string.output_trying_fallback_archs));
                            if (archs.contains("mips")) {
                                nextEabi = "mips";
                            }
                            if (archs.contains("x86")) {
                                nextEabi = "x86";
                            }
                            if (archs.contains("arm")) {
                                nextEabi = "armeabi";
                            }
                            doneFallback=true;
                            downloadBinary(prefixfn, nextEabi);
                        }
                    } else {
                        outputView.append(getString(R.string.output_trying_following_arch) + nextEabi + "\n");
                        // Toast.makeText(context, getString(R.string.toast_download_binary_nextarch)+ nextEabi,Toast.LENGTH_LONG).show();
                        downloadBinary(prefixfn, nextEabi);
                    }
                    return;
                }

                outputView.append(getString(R.string.toast_download_binary_ok) + "\n");
                //Toast.makeText(context,getString(R.string.toast_download_binary_ok), Toast.LENGTH_SHORT).show();

                String bindir = getFilesDir().getParent() + "/bin/";

                final UnzipTask binzipTask = new UnzipTask(this.context) {
                    @Override
                    protected void onPostExecute(String result) {
                        sharedProgressDialog.dismiss();
                        outputView.append(getString(R.string.toast_binary_extraction_ok)+"\n");
//                        Toast.makeText(context,getString(R.string.toast_binary_extraction_ok), Toast.LENGTH_SHORT).show();
                        Log.i("NetworkMapper","Completed. Directory: "+result);
                        String bindir = getFilesDir().getParent() + "/bin/";
                        String[] commands = {"ncat", "ndiff", "nmap", "nping"};
                        try {
                            for (String singlecommand : commands) {
                                Runtime.getRuntime().exec("/system/bin/chmod 755 " + bindir + singlecommand);
                            }
                        } catch (IOException e) {
                            outputView.append(getString(R.string.output_error_setting_permission)+"\n");
                            // Toast.makeText(context,"Error setting permissions", Toast.LENGTH_SHORT).show();
                            Log.e("NetworkMapper","IO Exception: \n"+e.toString());
                        }

                        Log.i("NetworkMapper","Data: Using prefix: "+dlprefix);

                        File myDir = new File(datadldir+"/"+dlprefix);

                        if(myDir.isDirectory()) {
                            DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    if (which == DialogInterface.BUTTON_POSITIVE) {
                                        downloadData(dlprefix);
                                    } else {
                                        SharedPreferences sharedPref = context.getSharedPreferences(context.getPackageName() + "_preferences", Context.MODE_PRIVATE);
                                        SharedPreferences.Editor editor = sharedPref.edit();
                                        editor.putString(getString(R.string.nmapbin_version), prefixfn);
                                        editor.apply();
                                    }
                                }
                            };

                            AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                            builder.setMessage(getString(R.string.dlg_ask2downloaddata))
                                    .setPositiveButton(getString(R.string.dlg_ask2download_yes), dialogClickListener)
                                    .setNegativeButton(getString(R.string.dlg_ask2download_no), dialogClickListener)
                                    .show();
                        } else {
                            downloadData(dlprefix);
                        }
                    }
                };
                binzipTask.execute(dlfn, bindir, dlprefix);

                sharedProgressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
                    @Override
                    public void onCancel(DialogInterface dialog) {
                        binzipTask.cancel(true);
                    }
                });

                mWakeLock.release();
            }
        };
        binaryTask.execute(nmapurl+"/"+binaryfn, dldir + "/" + binaryfn, prefixfn, appdir);

        sharedProgressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialog) {
                binaryTask.cancel(true);
            }
        });
    }

    private void downloadData(final String prefixfn) {
        String root = Environment.getExternalStorageDirectory().toString();
        final String datadldir = root + "/opt";

        Log.i("NetworkMapper", "Using datadldir: " + datadldir);
        makedir(datadldir);

        String datafn = prefixfn + "-data.zip";

        outputView.append(getString(R.string.output_download_datafn)+datafn+"\n");

        final DownloadTask dataTask = new DownloadTask(this) {
            @Override
            protected void onPostExecute(String result) {
                sharedProgressDialog.dismiss();
                if (result != null) {
                    outputView.append(getString(R.string.toast_data_download_error) + result);
                    // Toast.makeText(context, getString(R.string.toast_data_download_error) + result, Toast.LENGTH_LONG).show();
                    mWakeLock.release();
                    return;
                }
                outputView.append(getString(R.string.toast_data_download_ok) + "\n");
                // Toast.makeText(context, getString(R.string.toast_data_download_ok), Toast.LENGTH_SHORT).show();

                String datadir = Environment.getExternalStorageDirectory().toString() + "/opt/";
                final UnzipTask datazipTask = new UnzipTask(this.context) {
                    @Override
                    protected void onPostExecute(String result) {
                        SharedPreferences sharedPref = context.getSharedPreferences(context.getPackageName() + "_preferences",Context.MODE_PRIVATE);
                        final String oldver=sharedPref.getString(getString(R.string.nmapbin_version),"");

                        if (!oldver.equals("") && !oldver.equals(prefixfn)) {
                            SharedPreferences.Editor editor = sharedPref.edit();
                            editor.putString(getString(R.string.nmapbin_version), prefixfn);
                            editor.apply();
                            DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    if (which == DialogInterface.BUTTON_POSITIVE) {
                                        Log.i("NetworkMapper","deleting recursively!");
                                        DeleteRecursive(new File(datadldir + "/" + oldver));
                                    }
                                }
                            };

                            AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                            builder.setMessage(getString(R.string.dlg_ask2deletedata)+" "+oldver)
                                    .setPositiveButton(getString(R.string.dlg_ask2delete_yes), dialogClickListener)
                                    .setNegativeButton(getString(R.string.dlg_ask2delete_no), dialogClickListener)
                                    .show();
                        } else {
                            Log.i("NetworkMapper","No need to delete recursively!");
                        }
                        sharedProgressDialog.dismiss();
                        Toast.makeText(context, getString(R.string.toast_data_extraction_ok), Toast.LENGTH_SHORT).show();
                        Log.i("NetworkMapper", "Data Completed. Directory: " + result);

                        // Everything is finished: download and unzipping, check & display
                        isBinaryHere(true);
                    }

                    void DeleteRecursive(File fileOrDirectory) {
                        if (fileOrDirectory.isDirectory())
                            for (File child : fileOrDirectory.listFiles())
                                DeleteRecursive(child);

                        fileOrDirectory.delete();
                    }

                };
                datazipTask.execute(dlfn, datadir, dlprefix);

                sharedProgressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
                    @Override
                    public void onCancel(DialogInterface dialog) {
                        datazipTask.cancel(true);
                    }
                });

                mWakeLock.release();
            }
        };
        Log.i("NetworkMapper", "Executing using: " + nmapurl + "/" + datafn );
        dataTask.execute(nmapurl + "/" + datafn, datadldir + "/" + datafn, prefixfn, datadldir);

        sharedProgressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialog) {
                dataTask.cancel(true);
            }
        });
    }

    private void makedir (String dir) {
        File myDir = new File(dir);

        if(!myDir.isDirectory()) {
            myDir.mkdirs();
        }
    }

}
