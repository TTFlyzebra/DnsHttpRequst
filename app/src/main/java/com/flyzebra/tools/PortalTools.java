/**
 * FileName: PortalTools
 * Author: FlyZebra
 * Email:flycnzebra@gmail.com
 * Date: 2019/9/22 11:02
 * Description:
 */
package com.flyzebra.tools;

import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkInfo;
import android.text.TextUtils;

public class PortalTools {
    private static final String DEFAULT_IP = "203.208.40.63";
    public static int isWifiSetPortal(ConnectivityManager cm, String host, String dns1) {
        boolean setDefult = false;
        Network defaultNetwork = cm.getActiveNetwork();
        FlyLog.d("Active Network:" + defaultNetwork);
        Network[] networks = cm.getAllNetworks();
        for (Network network : networks) {
            NetworkInfo netInfo = cm.getNetworkInfo(network);
            if (netInfo != null && (netInfo.getType() == ConnectivityManager.TYPE_WIFI)) {
                setDefult = cm.bindProcessToNetwork(network);
            }
            if (setDefult) {
                FlyLog.d("Bind Network:" + network);
                FlyLog.d("Active Network:" + cm.getActiveNetwork());
                break;
            }
        }
        String ip = DnsTools.getIPbyHost(host, dns1);
        if (TextUtils.isEmpty(ip)) {
            ip = DEFAULT_IP;
        }
        int code = HttpTools.getHttpCode(host, ip);
        FlyLog.d("Get HTTP Code=%d", code);
        cm.bindProcessToNetwork(null);
        FlyLog.d("Active Network:" + cm.getActiveNetwork());
        return code;
    }
}
