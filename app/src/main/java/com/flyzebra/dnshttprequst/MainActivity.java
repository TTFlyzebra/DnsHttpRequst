package com.flyzebra.dnshttprequst;

import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.text.TextUtils;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.flyzebra.tools.FlyLog;
import com.flyzebra.tools.FlyDnsTools;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;

public class MainActivity extends AppCompatActivity {
    private static final HandlerThread sWorkerThread = new HandlerThread("http-task");

    static {
        sWorkerThread.start();
    }

    private static final Handler tHandler = new Handler(sWorkerThread.getLooper());
    private static Handler mHandler = new Handler(Looper.getMainLooper());

    private TextView textView;
    private StringBuffer stringBuffer = new StringBuffer();
    private String host = "connectivitycheck.gstatic.com";
    private String dns1 = "8.8.8.8";
    private static final String DEFAULT_IP = "203.208.40.63";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        textView = findViewById(R.id.ac_main_tv01);
    }

    public int sendGet(String host, String ip) {
        Socket socket;
        BufferedReader bufferedReader;
        BufferedWriter bufferedWriter;
        try {
            String lo = getIpAddress("wlan0");
            if (TextUtils.isEmpty(lo)) {
                lo = "0.0.0.0";
            }
            FlyLog.d("local ip=" + lo);
            InetAddress localAddress = InetAddress.getByName(lo);
            socket = new Socket(ip, 80, localAddress, 0);
            OutputStreamWriter streamWriter = new OutputStreamWriter(socket.getOutputStream());
            bufferedWriter = new BufferedWriter(streamWriter);
            bufferedWriter.write("GET /generate_204 HTTP/1.1\r\n");
            bufferedWriter.write("Host: " + host + "\r\n");
            bufferedWriter.write("\r\n");
            bufferedWriter.flush();
            BufferedInputStream streamReader = new BufferedInputStream(socket.getInputStream());
            bufferedReader = new BufferedReader(new InputStreamReader(streamReader, StandardCharsets.UTF_8));
            String statusLine = bufferedReader.readLine();
            if (TextUtils.isEmpty(statusLine)) {
                FlyLog.d("Http result empty");
                return 204;
            } else {
                FlyLog.d(statusLine);
                if (statusLine.startsWith("HTTP/1.")) {
                    int codePos = statusLine.indexOf(' ');
                    if (codePos > 0) {
                        int phrasePos = statusLine.indexOf(' ', codePos + 1);
                        if (phrasePos < 0)
                            phrasePos = statusLine.length();
                        try {
                            return Integer.parseInt(statusLine.substring(codePos + 1, phrasePos));
                        } catch (NumberFormatException e) {
                            return 204;
                        }
                    }
                }
            }
            bufferedReader.close();
            bufferedWriter.close();
            socket.close();
        } catch (Exception e) {
            FlyLog.e(e.toString());
        }
        return 204;
    }

    public static String getIpAddress(String netInterface) {
        String hostIp = null;
        try {
            Enumeration nis = NetworkInterface.getNetworkInterfaces();
            InetAddress ia = null;
            while (nis.hasMoreElements()) {
                NetworkInterface ni = (NetworkInterface) nis.nextElement();
                //Log.d(TAG,"getIpAddress,interface:"+ni.getName());
                if (ni.getName().equals(netInterface)) {
                    Enumeration<InetAddress> ias = ni.getInetAddresses();
                    while (ias.hasMoreElements()) {
                        ia = ias.nextElement();
                        if (ia instanceof Inet6Address) {
                            continue;// skip ipv6
                        }
                        String ip = ia.getHostAddress();
                        // 过滤掉127段的ip地址
                        if (!"127.0.0.1".equals(ip)) {
                            hostIp = ia.getHostAddress();
                            break;
                        }
                    }
                }
            }
        } catch (SocketException e) {
            FlyLog.e(e.toString());
            e.printStackTrace();
        }
        FlyLog.d("getIpAddress,interface:" + netInterface + ",ip:" + hostIp);
        return hostIp;
    }

    public void test(View view) {
        tHandler.removeCallbacksAndMessages(null);
        tHandler.post(new Runnable() {
            @Override
            public void run() {
                stringBuffer.setLength(0);
                upTextView();
                stringBuffer.append("待解析域名：").append(host).append("\nDNS服务器：").append(dns1).append("\n\n开始解析DNS......\n");
                upTextView();
                String ip = FlyDnsTools.getIPbyHost(host, dns1);
                stringBuffer.append("\n获取IP地址：").append(ip);
                upTextView();
                if(TextUtils.isEmpty(ip)){
                    ip = DEFAULT_IP;
                    stringBuffer.append("\n解析IP地址失败使用默认IP：").append(ip);
                }
                int code = sendGet(host, ip);
                stringBuffer.append("\nHttp Code：").append(code);
                upTextView();
                FlyLog.d("Get HTTP Code=%d", code);
            }
        });
    }

    private void upTextView() {
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                textView.setText(stringBuffer.toString());
            }
        });
    }
}
