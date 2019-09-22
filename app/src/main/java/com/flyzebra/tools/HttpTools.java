/**
 * FileName: HttpTools
 * Author: FlyZebra
 * Email:flycnzebra@gmail.com
 * Date: 2019/9/22 8:49
 * Description: socket send http request
 */
package com.flyzebra.tools;

import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkInfo;
import android.text.TextUtils;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;

public class HttpTools {
    public static int getHttpCode(String host, String ip) {
        FlyLog.d("ip=%s,host=%s",ip,host);
        Socket socket = null;
        BufferedReader bufferedReader = null;
        BufferedWriter bufferedWriter = null;
        try {
//            String lo = getIpAddress("wlan0");
//            if (TextUtils.isEmpty(lo)) {
//                lo = "0.0.0.0";
//            }
//            FlyLog.d("local ip=" + lo);
//            InetAddress localAddress = InetAddress.getByName(lo);
//            socket = new Socket(ip, 80, localAddress, 0);

            SocketAddress socketAddress = new InetSocketAddress(ip, 80);
            socket = new Socket();
            socket.setSoTimeout(5000);
            socket.connect(socketAddress);

            FlyLog.d("localAddress:"+socket.getLocalAddress());

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
        }finally {
            try {
                if (bufferedReader != null) {
                    bufferedReader.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                if (bufferedWriter != null) {
                    bufferedWriter.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
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

}
