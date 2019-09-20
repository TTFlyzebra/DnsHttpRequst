package com.flyzebra.dnshttprequst;

import com.flyzebra.dnshttprequst.Dns.Dnsdefine;
import com.flyzebra.dnshttprequst.Dns.Head;
import com.flyzebra.dnshttprequst.Dns.Queries;
import com.flyzebra.dnshttprequst.Dns.RR;
import com.flyzebra.dnshttprequst.util.Util;

import java.io.IOException;
import java.net.*;
import java.util.Random;

public class DnsTools {

    static byte sendbyte[] = {
            (byte) 0x45, (byte) 0x00, (byte) 0x00, (byte) 0x4b, (byte) 0x9f, (byte) 0xf2, (byte) 0x40, (byte) 0x00,
            (byte) 0x40, (byte) 0x11, (byte) 0x87, (byte) 0xbb, (byte) 0xc0, (byte) 0xa8, (byte) 0x01, (byte) 0x66,
            (byte) 0xca, (byte) 0x60, (byte) 0x86, (byte) 0x85, (byte) 0x33, (byte) 0x52, (byte) 0x00, (byte) 0x35,
            (byte) 0x00, (byte) 0x37, (byte) 0x6f, (byte) 0x30, (byte) 0x08, (byte) 0x85, (byte) 0x01, (byte) 0x00,
            (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x11, (byte) 0x63, (byte) 0x6f, (byte) 0x6e, (byte) 0x6e, (byte) 0x65, (byte) 0x63, (byte) 0x74,
            (byte) 0x69, (byte) 0x76, (byte) 0x69, (byte) 0x74, (byte) 0x79, (byte) 0x63, (byte) 0x68, (byte) 0x65,
            (byte) 0x63, (byte) 0x6b, (byte) 0x07, (byte) 0x67, (byte) 0x73, (byte) 0x74, (byte) 0x61, (byte) 0x74,
            (byte) 0x69, (byte) 0x63, (byte) 0x03, (byte) 0x63, (byte) 0x6f, (byte) 0x6d, (byte) 0x00, (byte) 0x00,
            (byte) 0x1c, (byte) 0x00, (byte) 0x01};

    public static String revQuery(String domin, final String HostAddress) {
        FlyLog.d(domin);
        FlyLog.d(HostAddress);
        Random rand = new Random();
        /* String HostAddress = "198.41.0.4"; //域名服务器*/
        //顶级域名：198.41.0.4  192.5.6.30   202.108.22.220  61.135.165.224
        Util.init();
        //生成需要发送的额数据
        short transid = (short) rand.nextInt(1000);
        final Head head = new Head(transid, (short) 0x0100, (short) 1, (short) 0, (short) 0, (short) 0);
        final Queries queries = new Queries(domin, "A");
        final Dnsdefine data = new Dnsdefine(head, queries);
        final byte[] msg = data.Sendmsgbyte();
        FlyLog.d("----------数据准备完毕 开始发送udp--------------");
        final byte[] rec = new byte[1024];

        try {
            DatagramSocket ds = new DatagramSocket();
            //向dns 发送报文
            DatagramPacket senddp = new DatagramPacket(sendbyte, sendbyte.length, InetAddress.getByName(HostAddress), 53);
            ds.send(senddp);
            FlyLog.d(senddp.getAddress().getHostAddress() + "         " + senddp.getPort() + "         " + senddp.getData().toString());
            //接受报文
            DatagramPacket recdp = new DatagramPacket(rec, rec.length);
            ds.receive(recdp);
            String ip = recdp.getAddress().getHostAddress();
            int port = recdp.getPort();
            String str = new String(recdp.getData(), 0, recdp.getData().length);
            FlyLog.d(ip + ":" + port + "----->" + recdp.getData() + " -----len" + recdp.getData().length);
            FlyLog.d(Util.byte2hex(str.getBytes()));
            //开始头部解析事件
            int HeadLen = head.getHead().length;
            int QueriesLen = queries.getQueries().length;
            int domianlen = queries.getNameLen();
            int curLen = 0;
            byte[] recHead = new byte[head.getHead().length];
            System.arraycopy(recdp.getData(), 0, recHead, 0, head.getHead().length);
            Head RecvHead = new Head(recHead);
            FlyLog.d("head: " + Util.byte2hex(RecvHead.getHead()));
            FlyLog.d("Questions:" + RecvHead.getQuestions());
            FlyLog.d("AnswerRRs: " + RecvHead.getAnswerRRs());
            FlyLog.d("AnswerRRs: " + RecvHead.getAuthorityRRs());
            FlyLog.d("AnswerRRs: " + RecvHead.getAddtitionalRRs());
            curLen = HeadLen;
            /*----------------------开始解析queries----------------------*/
            byte[] recQuerise = new byte[QueriesLen];
            System.arraycopy(recdp.getData(), curLen, recQuerise, 0, QueriesLen);
            Queries RecvQue = new Queries(recQuerise);
            //存储结果
            Dnsdefine result = new Dnsdefine(RecvHead, RecvQue);
            /*---------------开始解析answer部分---------------*/
            curLen += QueriesLen; //记录当前获得的应该获取byte
            RR[] rr = new RR[3];
            for (int i = 0; i < RecvHead.getAnswerRRs(); i++) {
                //对每一个answer解析
                byte[] Answer = new byte[200];
                System.arraycopy(recdp.getData(), curLen, Answer, 0, 12);
                rr[i] = new RR(Answer);
                byte[] ans_data = new byte[rr[i].getDatalength()];
                System.arraycopy(recdp.getData(), curLen + 12, ans_data, 0, rr[i].getDatalength());
                if (rr[i].getType() == Util.getType("CNAME")) {
                    String newDomin = Util.transfer(ans_data, queries.getName().getBytes());
                    //FlyLog.d(newDomin);
                    rr[i].setData(newDomin);
                } else if (rr[i].getType() == Util.getType("A")) {
                    String addr = Util.getAddr(ans_data);
                    //FlyLog.d(addr);
                    rr[i].setData(addr);
                } else if (rr[i].getType() == Util.getType("AAAA")) {
                    //FlyLog.d(i + ":   ipv6_data:" + Util.byte2hex(ans_data));
                    //FlyLog.d();
                    String addr6 = Util.getAddr(ans_data);
                    rr[i].setData(addr6);
                }
                curLen += 12 + rr[i].getDatalength();
            }
            result.setAnswerRRs(rr);
            FlyLog.d(result.printfinfo());

        } catch (SocketException e) {
            e.printStackTrace();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String IterQuery(String domin, final String HostAddress) {
        FlyLog.d(domin);
        FlyLog.d(HostAddress);
        Random rand = new Random();
        Util.init();
        //生成需要发送的额数据
        short transid = (short) rand.nextInt(1000);
        final Head head = new Head(transid, (short) 0x0100, (short) 1, (short) 0, (short) 0, (short) 0);
        final Queries queries = new Queries(domin, "A");
        final Dnsdefine data = new Dnsdefine(head, queries);
        final byte[] msg = data.Sendmsgbyte();
        FlyLog.d("----------数据准备完毕 开始发送udp--------------");
        final byte[] rec = new byte[1024];
        try {
            DatagramSocket ds = new DatagramSocket();
            //向dns 发送报文
            DatagramPacket senddp = new DatagramPacket(msg, msg.length, InetAddress.getByName(HostAddress), 53);
            ds.send(senddp);
            FlyLog.d(senddp.getAddress().getHostAddress() + "         " + senddp.getPort() + "         " + senddp.getData().toString());
            //接受报文
            DatagramPacket recdp = new DatagramPacket(rec, rec.length);
            ds.receive(recdp);
            String ip = recdp.getAddress().getHostAddress();
            int port = recdp.getPort();
            String str = new String(recdp.getData(), 0, recdp.getData().length);
            FlyLog.d(ip + ":" + port + "----->" + recdp.getData() + " -----len:" + recdp.getData().length);
            FlyLog.d(Util.byte2hex(str.getBytes()));
            //开始头部解析事件
            int HeadLen = head.getHead().length;
            int QueriesLen = queries.getQueries().length;
            int domianlen = queries.getNameLen();
            int curLen = 0;

            byte[] recHead = new byte[head.getHead().length];
            System.arraycopy(recdp.getData(), 0, recHead, 0, head.getHead().length);
            Head RecvHead = new Head(recHead);
            FlyLog.d("head: " + Util.byte2hex(RecvHead.getHead()));
            FlyLog.d("Questions:" + RecvHead.getQuestions());
            FlyLog.d("AnswerRRs: " + RecvHead.getAnswerRRs());
            FlyLog.d("AnswerRRs: " + RecvHead.getAuthorityRRs());
            FlyLog.d("AnswerRRs: " + RecvHead.getAddtitionalRRs());
            curLen = HeadLen;

            /*----------------------开始解析queries----------------------*/
            byte[] recQuerise = new byte[QueriesLen];
            System.arraycopy(recdp.getData(), curLen, recQuerise, 0, QueriesLen);
            Queries RecvQue = new Queries(recQuerise);
            //存储结果
            Dnsdefine result = new Dnsdefine(RecvHead, RecvQue);
            /*---------------开始解析answer部分---------------*/
            curLen += QueriesLen; //记录当前获得的应该获取byte
            RR[] rr = new RR[3];
            for (int i = 0; i < RecvHead.getAnswerRRs(); i++) {
                //对每一个answer解析
                byte[] Answer = new byte[200];
                System.arraycopy(recdp.getData(), curLen, Answer, 0, 12);
                rr[i] = new RR(Answer);
                byte[] ans_data = new byte[rr[i].getDatalength()];
                System.arraycopy(recdp.getData(), curLen + 12, ans_data, 0, rr[i].getDatalength());
                if (rr[i].getType() == Util.getType("CNAME")) {
                    String newDomin = Util.transfer(ans_data, queries.getName().getBytes());
                    //FlyLog.d(newDomin);
                    rr[i].setData(newDomin);
                } else if (rr[i].getType() == Util.getType("A")) {
                    String addr = Util.getAddr(ans_data);
                    //FlyLog.d(addr);
                    rr[i].setData(addr);
                } else if (rr[i].getType() == Util.getType("AAAA")) {
                    //FlyLog.d(i + ":   ipv6_data:" + Util.byte2hex(ans_data));
                    //FlyLog.d();
                    String addr6 = Util.getAddr(ans_data);
                    rr[i].setData(addr6);
                }
                curLen += 12 + rr[i].getDatalength();
            }
            result.setAnswerRRs(rr);
            //data.setAddtitionalRRs();
            //开始解析 authorityRRs
            FlyLog.d("----------------开始解析 authorityRRs--------------");
            RR[] auto = new RR[RecvHead.getAuthorityRRs()];
            for (int i = 0; i < RecvHead.getAuthorityRRs(); i++) {
                //对每一个answer解析
                byte[] Answer = new byte[200];
                System.arraycopy(recdp.getData(), curLen, Answer, 0, 12);
                //FlyLog.d("截取answer："+ Util.byte2hex(Answer));
                auto[i] = new RR(Answer);
                //FlyLog.d("ans: "+ Util.byte2hex(auto[i].getinfoByte()));
                //FlyLog.d(rr[i].getDatalength());
                byte[] ans_data = new byte[auto[i].getDatalength()];
                System.arraycopy(recdp.getData(), curLen + 12, ans_data, 0, auto[i].getDatalength());
                //FlyLog.d(Util.byte2hex(ans_data));
                //FlyLog.d(Util.bytetoSting(ans_data));
                if (auto[i].getType() == Util.getType("CNAME")) {
                    String newDomin = Util.transfer(ans_data, queries.getName().getBytes());
                    //FlyLog.d(newDomin);
                    auto[i].setData(newDomin);

                } else if (auto[i].getType() == Util.getType("A")) {
                    String addr = Util.getAddr(ans_data);
                    auto[i].setData(addr);
                    //FlyLog.d(addr);
                } else if (auto[i].getType() == Util.getType("NS")) {
                    //对地柜解析过程中得到的nS类型数据的解析
                    //FlyLog.d("ns_data:" + Util.byte2hex(ans_data));
                    String nsserver = Util.trandNs(ans_data, recdp.getData());
                    auto[i].setData(nsserver);
                    // FlyLog.d(nsserver);
                }
                curLen += 12 + auto[i].getDatalength();
            }
            result.setAuthorityRRs(auto);
            FlyLog.d("----------------开始解析additionnalRRs--------------");
            RR[] addition = new RR[RecvHead.getAddtitionalRRs()];
            for (int i = 0; i < RecvHead.getAddtitionalRRs(); i++) {
                //对每一个answer解析
                byte[] Answer = new byte[200];
                System.arraycopy(recdp.getData(), curLen, Answer, 0, 12);
                //FlyLog.d("截取answer："+ Util.byte2hex(Answer));
                addition[i] = new RR(Answer);
                //FlyLog.d("ans: "+ Util.byte2hex(addition[i].getinfoByte()));
                //FlyLog.d(rr[i].getDatalength());
                byte[] ans_data = new byte[addition[i].getDatalength()];
                System.arraycopy(recdp.getData(), curLen + 12, ans_data, 0, addition[i].getDatalength());
                //FlyLog.d(Util.byte2hex(ans_data));
                //FlyLog.d(Util.bytetoSting(ans_data));
                if (addition[i].getType() == Util.getType("CNAME")) {
                    String newDomin = Util.transfer(ans_data, queries.getName().getBytes());
                    FlyLog.d(newDomin);
                    addition[i].setData(newDomin);
                } else if (addition[i].getType() == Util.getType("A")) {
                    FlyLog.d(i + ":   ip4_addr:" + Util.byte2hex(ans_data));
                    String addr = Util.getAddr(ans_data);
                    FlyLog.d(addr);
                    addition[i].setData(addr);
                } else if (addition[i].getType() == Util.getType("NS")) {
                    //对地柜解析过程中得到的nS类型数据的解析
                    FlyLog.d(i + ":   ns_data:" + Util.byte2hex(ans_data));
                    String nsserver = Util.trandNs(ans_data, recdp.getData());
                    FlyLog.d(nsserver);
                    addition[i].setData(nsserver);
                } else if (addition[i].getType() == Util.getType("AAAA")) {
                    FlyLog.d(i + ":   ipv6_data:" + Util.byte2hex(ans_data));
                    FlyLog.d(Util.getAddr6(ans_data));
                    addition[i].setData(Util.getAddr6(ans_data));
                }
                curLen += 12 + addition[i].getDatalength();
            }
            result.setAddtitionalRRs(addition);
            FlyLog.d(result.printfinfo());
        } catch (SocketException e) {
            e.printStackTrace();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void test() {
/*	// write your code here
        byte [] ba = {1, 2, 3, 4};
        FlyLog.d(ba[0]+" --> "+ba[1]+" --> "+ba[2]+" --> "+ba[3]+" --> ");
// 4 bytes to int
        int in = ByteBuffer.wrap(ba).order(ByteOrder.LITTLE_ENDIAN).getInt();
        FlyLog.d(in);

        byte [] ab = null;

// int to 4 bytes method 1
        ab = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(in).array();
        FlyLog.d(ab[0]+" --> "+ab[1]+" --> "+ab[2]+" --> "+ab[3]+" --> ");


        // int to 4 bytes method 2
        ab = new byte[4];
        ByteBuffer.wrap(ab).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().put(in);
        FlyLog.d(ab[0]+" --> "+ab[1]+" --> "+ab[2]+" --> "+ab[3]+" --> ");

        short t = 0x0010;
        FlyLog.d(t);
        byte[] test = Util.shortToBytes(t);
        short ans = Util.byteCattoShort(test);
        FlyLog.d(ans);

        short x = -32752;//定义一个short
        byte high = (byte) (0x00FF & (x>>8));//定义第一个byte
        byte low = (byte) (0x00FF & x);//定义第二个byte
        FlyLog.d(high);//打印第一个byte值
        FlyLog.d(low);//打印第二个byte值
        // 复原
        short z = (short)(((high & 0x00FF) << 8) | (0x00FF & low));
        FlyLog.d(z);//输出的结果就是-32752*/

        String domin = "ded.nuaa.edu.cn";//请求的域名  //www.a.shifen.com
        Random rand = new Random();
        final int port = rand.nextInt(48000) + 1024;
        final String HostAddress = "198.41.0.4"; //域名服务器
        //顶级域名：198.41.0.4  192.5.6.30   202.108.22.220  61.135.165.224

        //开始准备数据
        Util.init();
        //生成需要发送的额数据
        short transid = (short) rand.nextInt(1000);
        final Head head = new Head(transid, (short) 0x0100, (short) 1, (short) 0, (short) 0, (short) 0);
        FlyLog.d("head:  ");
        FlyLog.d(Util.byte2hex(head.getHead()));

        final Queries queries = new Queries(domin, "A");
        FlyLog.d("queries:");
        FlyLog.d(Util.byte2hex(queries.getQueries()));

        final Dnsdefine data = new Dnsdefine(head, queries);
        final byte[] msg = data.Sendmsgbyte();

        FlyLog.d("--------------------------------------");
        FlyLog.d("final packet:  " + Util.byte2hex(msg));
        //将byte[] 转化为String
        //Base64 Encoded
//        String encoded = Base64.getEncoder().encodeToString(msg);
//        //Base64 Decoded
//        byte[] decoded = Base64.getDecoder().decode(encoded);
//        //Verify original content
//        FlyLog.d( new String(decoded) );


        final byte[] rec = new byte[1024];
        FlyLog.d("----------数据准备完毕 开始发送udp--------------");
        //数据准备完毕 开始发送udp

/*        Thread t = new Thread(){
            @Override
            public void run() {
                //子线程访问网络
                try {
                    DatagramSocket ds = new DatagramSocket(port);
                    //向dns 发送报文
                    FlyLog.d("send befor:   "+Util.bytetoSting(msg));
                    //DatagramPacket senddp = new DatagramPacket(msg,msg.length,InetAddress.getByName(HostAddress),53);
                    DatagramPacket senddp = new DatagramPacket(msg,msg.length,InetAddress.getByName("101.226.4.6"),53);
                    ds.send(senddp);
                    *//*
         * test
         * *//*
                    FlyLog.d(senddp.getAddress().getHostAddress());
                    FlyLog.d(senddp.getPort());
                    FlyLog.d(senddp.getData().toString() +"         "+senddp.getData().length);

                    //接受报文
                    DatagramPacket recdp = new DatagramPacket(rec,rec.length);
                    FlyLog.d("star recive");
                    ds.receive(recdp);
                    FlyLog.d("end recive");
                    String ip = recdp.getAddress().getHostAddress();
                    int  port = recdp.getPort();
                    String data = new String(recdp.getData(),0,recdp.getData().length);
                    FlyLog.d(ip +":"+ port +"----->"+ recdp.getData() +" -----len"+recdp.getData().length);
                    FlyLog.d(data+"----------len"+data.length());
                    FlyLog.d(Util.byte2hex(data.getBytes()));

                    //开始头部解析事件
                    int HeadLen = head.getHead().length;
                    int QueriesLen = queries.getQueries().length;
                    int domianlen = queries.getNameLen();
                    int curLen = 0;

                    byte[] recHead = new byte[head.getHead().length];
                    System.arraycopy(recdp.getData(), 0, recHead , 0, head.getHead().length);
                    Head RecvHead = new Head(recHead);
                    FlyLog.d("head: " + Util.byte2hex(recHead));
                    FlyLog.d("head: "+ Util.byte2hex(RecvHead.getHead()));
                    FlyLog.d("Questions:" + RecvHead.getQuestions());
                    FlyLog.d("AnswerRRs: "+RecvHead.getAnswerRRs());
                    FlyLog.d("AnswerRRs: "+RecvHead.getAuthorityRRs());
                    FlyLog.d("AnswerRRs: "+RecvHead.getAddtitionalRRs());

                    FlyLog.d("截取后剩余的： "+Util.byte2hex(recdp.getData()));


                    *//*FlyLog.d("-----------------------------------------");
                    byte[] test = Util.intToByteArray(1152);
                    FlyLog.d(Util.byte2hex(test));//0000 0480
                    int ans = Util.byteCattoInt(test);
                    FlyLog.d(ans);*//*

         *//*---------------开始解析answer部分---------------*//*
                    curLen = HeadLen+QueriesLen; //记录当前获得的应该获取byte
                    RR[] rr = new RR[3];
                    for (int i=0;i< RecvHead.getAnswerRRs();i++){
                        //对每一个answer解析
                        byte[] Answer = new byte[200];
                        System.arraycopy(recdp.getData(),curLen,Answer,0,12);
                        //FlyLog.d("截取answer："+ Util.byte2hex(Answer));
                        rr[i] = new RR(Answer);
                        FlyLog.d("ans: "+ Util.byte2hex(rr[i].getinfoByte()));
                        //FlyLog.d(rr[i].getDatalength());
                        byte[] ans_data = new byte[rr[i].getDatalength()];
                        System.arraycopy(recdp.getData(),curLen+12,ans_data,0,rr[i].getDatalength());
                        //FlyLog.d(Util.byte2hex(ans_data));
                        //FlyLog.d(Util.bytetoSting(ans_data));
                        if (rr[i].getType() == Util.getType("CNAME")){
                            String newDomin = Util.transfer(ans_data,queries.getName().getBytes());
                            FlyLog.d(newDomin);
                        }else if (rr[i].getType() == Util.getType("A")){
                            String addr = Util.getAddr(ans_data);
                            FlyLog.d(addr);
                        }
                        curLen += 12 + rr[i].getDatalength();
                    }

                } catch (SocketException e) {
                    e.printStackTrace();
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        };
        t.start();*/


        //迭代查询的过程
        Thread t2 = new Thread() {
            @Override
            public void run() {
                try {
                    DatagramSocket ds = new DatagramSocket(port);
                    //向dns 发送报文
                    FlyLog.d("send befor:   " + Util.bytetoSting(msg));
                    DatagramPacket senddp = new DatagramPacket(msg, msg.length, InetAddress.getByName(HostAddress), 53);
                    //DatagramPacket senddp = new DatagramPacket(msg, msg.length, InetAddress.getByName("101.226.4.6"), 53);
                    ds.send(senddp);

                    //接受报文
                    DatagramPacket recdp = new DatagramPacket(rec, rec.length);
                    //FlyLog.d("star recive");
                    ds.receive(recdp);
                    //FlyLog.d("end recive");
                    String ip = recdp.getAddress().getHostAddress();
                    int port = recdp.getPort();
                    String data = new String(recdp.getData(), 0, recdp.getData().length);
                    /*FlyLog.d(ip + ":" + port + "----->" + recdp.getData() + " -----len" + recdp.getData().length);
                    FlyLog.d(data + "----------len" + data.length());*/
                    FlyLog.d(Util.byte2hex(data.getBytes()));
                    //开始头部解析事件
                    int HeadLen = head.getHead().length;
                    int QueriesLen = queries.getQueries().length;
                    int domianlen = queries.getNameLen();
                    int curLen = 0;

                    byte[] recHead = new byte[head.getHead().length];
                    System.arraycopy(recdp.getData(), 0, recHead, 0, head.getHead().length);
                    Head RecvHead = new Head(recHead);
                    FlyLog.d("head: " + Util.byte2hex(recHead));
                    FlyLog.d("head: " + Util.byte2hex(RecvHead.getHead()));
                    FlyLog.d("Questions:" + RecvHead.getQuestions());
                    FlyLog.d("AnswerRRs: " + RecvHead.getAnswerRRs());
                    FlyLog.d("AnswerRRs: " + RecvHead.getAuthorityRRs());
                    FlyLog.d("AnswerRRs: " + RecvHead.getAddtitionalRRs());

                    FlyLog.d("截取后剩余的： " + Util.byte2hex(recdp.getData()));

                    //*---------------开始解析answer部分---------------*/
                    FlyLog.d("---------------开始解析answer部分---------------");
                    curLen = HeadLen + QueriesLen; //记录当前获得的应该获取byte
                    RR[] rr = new RR[RecvHead.getAnswerRRs()];
                    for (int i = 0; i < RecvHead.getAnswerRRs(); i++) {
                        //对每一个answer解析
                        byte[] Answer = new byte[200];
                        System.arraycopy(recdp.getData(), curLen, Answer, 0, 12);
                        //FlyLog.d("截取answer："+ Util.byte2hex(Answer));
                        rr[i] = new RR(Answer);
                        FlyLog.d("ans: " + Util.byte2hex(rr[i].getinfoByte()));
                        //FlyLog.d(rr[i].getDatalength());
                        byte[] ans_data = new byte[rr[i].getDatalength()];
                        System.arraycopy(recdp.getData(), curLen + 12, ans_data, 0, rr[i].getDatalength());
                        //FlyLog.d(Util.byte2hex(ans_data));
                        //FlyLog.d(Util.bytetoSting(ans_data));
                        if (rr[i].getType() == Util.getType("CNAME")) {
                            String newDomin = Util.transfer(ans_data, queries.getName().getBytes());
                            FlyLog.d(newDomin);
                        } else if (rr[i].getType() == Util.getType("A")) {
                            String addr = Util.getAddr(ans_data);
                            FlyLog.d(addr);
                        }
                        curLen += 12 + rr[i].getDatalength();
                    }

                    //data.setAddtitionalRRs();
                    //开始解析 authorityRRs
                    FlyLog.d("----------------开始解析 authorityRRs--------------");
                    RR[] auto = new RR[RecvHead.getAuthorityRRs()];
                    for (int i = 0; i < RecvHead.getAuthorityRRs(); i++) {
                        //对每一个answer解析
                        byte[] Answer = new byte[200];
                        System.arraycopy(recdp.getData(), curLen, Answer, 0, 12);
                        //FlyLog.d("截取answer："+ Util.byte2hex(Answer));
                        auto[i] = new RR(Answer);
                        //FlyLog.d("ans: "+ Util.byte2hex(auto[i].getinfoByte()));
                        //FlyLog.d(rr[i].getDatalength());
                        byte[] ans_data = new byte[auto[i].getDatalength()];
                        System.arraycopy(recdp.getData(), curLen + 12, ans_data, 0, auto[i].getDatalength());
                        //FlyLog.d(Util.byte2hex(ans_data));
                        //FlyLog.d(Util.bytetoSting(ans_data));
                        if (auto[i].getType() == Util.getType("CNAME")) {
                            String newDomin = Util.transfer(ans_data, queries.getName().getBytes());
                            FlyLog.d(newDomin);
                        } else if (auto[i].getType() == Util.getType("A")) {
                            String addr = Util.getAddr(ans_data);
                            FlyLog.d(addr);
                        } else if (auto[i].getType() == Util.getType("NS")) {
                            //对地柜解析过程中得到的nS类型数据的解析
                            FlyLog.d("ns_data:" + Util.byte2hex(ans_data));
                            String nsserver = Util.trandNs(ans_data, recdp.getData());
                            auto[i].setData(nsserver);
                            FlyLog.d(nsserver);
                        }
                        curLen += 12 + auto[i].getDatalength();
                    }

                    FlyLog.d("----------------开始解析additionnalRRs--------------");
                    RR[] addition = new RR[RecvHead.getAddtitionalRRs()];
                    for (int i = 0; i < RecvHead.getAddtitionalRRs(); i++) {
                        //对每一个answer解析
                        byte[] Answer = new byte[200];
                        System.arraycopy(recdp.getData(), curLen, Answer, 0, 12);
                        //FlyLog.d("截取answer："+ Util.byte2hex(Answer));
                        addition[i] = new RR(Answer);
                        //FlyLog.d("ans: "+ Util.byte2hex(addition[i].getinfoByte()));
                        //FlyLog.d(rr[i].getDatalength());
                        byte[] ans_data = new byte[addition[i].getDatalength()];
                        System.arraycopy(recdp.getData(), curLen + 12, ans_data, 0, addition[i].getDatalength());
                        //FlyLog.d(Util.byte2hex(ans_data));
                        //FlyLog.d(Util.bytetoSting(ans_data));
                        if (addition[i].getType() == Util.getType("CNAME")) {
                            String newDomin = Util.transfer(ans_data, queries.getName().getBytes());
                            FlyLog.d(newDomin);
                            addition[i].setData(newDomin);
                        } else if (addition[i].getType() == Util.getType("A")) {
                            FlyLog.d(i + ":   ip4_addr:" + Util.byte2hex(ans_data));
                            String addr = Util.getAddr(ans_data);
                            FlyLog.d(addr);
                            addition[i].setData(addr);
                        } else if (addition[i].getType() == Util.getType("NS")) {
                            //对地柜解析过程中得到的nS类型数据的解析
                            FlyLog.d(i + ":   ns_data:" + Util.byte2hex(ans_data));
                            String nsserver = Util.trandNs(ans_data, recdp.getData());
                            FlyLog.d(nsserver);
                            addition[i].setData(nsserver);
                        } else if (addition[i].getType() == Util.getType("AAAA")) {
                            FlyLog.d(i + ":   ipv6_data:" + Util.byte2hex(ans_data));
                            FlyLog.d(Util.getAddr6(ans_data));
                            addition[i].setData(Util.getAddr6(ans_data));
                        }
                        curLen += 12 + addition[i].getDatalength();
                    }


                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (SocketException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        };
        t2.start();

    }
}


