package com.flyzebra.dnshttprequst;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.text.TextUtils;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.flyzebra.tools.DnsTools;
import com.flyzebra.tools.FlyLog;
import com.flyzebra.tools.HttpTools;
import com.flyzebra.tools.PortalTools;

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
    private ConnectivityManager cm;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        cm = (ConnectivityManager) MainActivity.this.getSystemService(Context.CONNECTIVITY_SERVICE);

        textView = findViewById(R.id.ac_main_tv01);
    }

    public void verity(View view) {
        tHandler.removeCallbacksAndMessages(null);
        tHandler.post(new Runnable() {
            @Override
            public void run() {
                isWifiSetPortal();
//                int code = PortalTools.isWifiSetPortal(cm,host,dns1);
            }
        });
    }

    private int isWifiSetPortal() {
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
        stringBuffer.setLength(0);

        upTextView();
        stringBuffer.append("待解析域名：").
                append(host).
                append("\nDNS服务器：").
                append(dns1).
                append("\n\n开始解析域名......");
        upTextView();

        String ip = DnsTools.getIPbyHost(host, dns1);
        stringBuffer.append("\n获取域名地址：\n").
                append(ip);
        upTextView();

        stringBuffer.append("\n解析域名完成......");
        upTextView();
        stringBuffer.append("\n发送认证请求......");
        upTextView();
        if (TextUtils.isEmpty(ip)) {
            ip = DEFAULT_IP;
            stringBuffer.append("\n解析IP地址失败使用默认IP：").append(ip);
        }

        int code = HttpTools.getHttpCode(host, ip);
        stringBuffer.append("\n认证返回结果：【").append(code).append("】");
        upTextView();
        FlyLog.d("Get HTTP Code=%d", code);
        cm.bindProcessToNetwork(null);
        FlyLog.d("Active Network:" + cm.getActiveNetwork());
        return code;
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
