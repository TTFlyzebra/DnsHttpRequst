package com.flyzebra.tools;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class UdpDnsTools {
    private static byte dnsHead[] = {
            (byte) 0xFF, (byte) 0xFF,
            (byte) 0x01, (byte) 0x00,
            (byte) 0x00, (byte) 0x01,
            (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00};
    private static byte queries_end[] = {
            (byte) 0x00, (byte) 0x01,
            (byte) 0x00, (byte) 0x01,
    };

    /**
     * 返回DNS解析后的一个IP地址
     *
     * @param domin
     * @param HostAddress
     * @return
     */
    public static String getDns(String domin, final String HostAddress) {
        try {
            ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
            byteBuffer.put(dnsHead);
            String[] strs = domin.split("\\.");
            for (String s : strs) {
                byteBuffer.put((byte) s.length());
                byteBuffer.put(s.getBytes());
            }
            byteBuffer.put((byte) 0);
            byteBuffer.put(queries_end);
            byteBuffer.flip();
            int len = byteBuffer.limit() - byteBuffer.position();
            byte[] sendData = new byte[len];
            byteBuffer.get(sendData);
            FlyLog.d("send:%s", ByteTools.bytes2HexString(sendData));

            DatagramSocket socket = new DatagramSocket();
            socket.setSoTimeout(5000);
            DatagramPacket sendpack = new DatagramPacket(sendData, sendData.length, InetAddress.getByName(HostAddress), 53);
            socket.send(sendpack);

            final byte[] recvBuffer = new byte[1024];
            DatagramPacket recvpack = new DatagramPacket(recvBuffer, recvBuffer.length);
            socket.receive(recvpack);
            byte[] recvData = recvpack.getData();
            FlyLog.d(recvpack.getAddress().getHostAddress() + ":" + recvpack.getPort() + "--len" + recvpack.getData().length);
            FlyLog.d("recv:%s", ByteTools.bytes2HexString(recvData,64));
            int answer = ByteTools.bytes2Short2(recvData, 4);
            if (answer > 0) {
                ByteBuffer answerBuffer = ByteBuffer.wrap(recvData);
                answerBuffer.position(len);
                //  TYPE:回复的类型。2字节，与查询同义。指示RDATA中的资源记录类型。 
                //  CLASS:回复的类。2字节，与查询同义。指示RDATA中的资源记录类。 
                //  TTL:生存时间。4字节，指示RDATA中的资源记录在缓存的生存时间。 
                //  RDLENGTH:长度。2字节，指示RDATA块的长度。 
                for (; ; ) {
                    short name = answerBuffer.getShort();
                    if (name == 0) break;
                    short type = answerBuffer.getShort();
                    short _cls = answerBuffer.getShort();
                    int ttl = answerBuffer.getInt();
                    short length = answerBuffer.getShort();
                    byte[] content = new byte[length];
                    answerBuffer.get(content);
                    if (type == 1) {
                        String ip = (content[0] & 0xff) + "." + (content[1] & 0xff) + "." + (content[2] & 0xff) + "." + (content[3] & 0xff);
                        FlyLog.d("get ip address=%s",ip);
                        return ip;
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }


}


