package com.flyzebra.dnshttprequst.util;

import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Util {

    //读取本地缓存
    //刷新本地缓存 所使用的文件的位置
    public static String filePath = "H:\\java_code\\IdeaProjects\\DNS_simulate\\src\\com\\company\\util\\DnsBuf.txt"; //该文件每行一条记录

    public static Map<String, Short> map = new HashMap<>();

    public static void init() {
        map.put("A", (short) 1);//由域名获得IPv4地址
        map.put("NS", (short) 2);//	查询域名服务器
        map.put("CNAME", (short) 5);//查询规范名称
        map.put("SOA", (short) 6);//开始授权
        map.put("WKS", (short) 11);//熟知服务
        map.put("PTR", (short) 12);//把IP地址转换成域名
        map.put("HINFO", (short) 13);//主机信息
        map.put("MX", (short) 15);//邮件交换
        map.put("AAAA", (short) 28);//由域名获得IPv6地址
        map.put("AXFR", (short) 252);//传送整个区的请求
        map.put("ANY", (short) 255);//对所有记录的请求
    }

    public static String getKey(short value) {
        Map.Entry<String, Short> entry = null;
        Iterator<Map.Entry<String, Short>> entries = map.entrySet().iterator();
        while (entries.hasNext()) {
            entry = entries.next();
            if (value == entry.getValue())
                break;
        }
        return entry.getKey();
    }

    public static short getType(String key) {
        return map.get(key);
    }


    public static String transfer(String url) {
        //实现对url 的格式装换
        String[] buf = url.split("\\.");
        int len = buf.length;
        String res = new String();
        for (int i = 0; i < len; i++) {
            char[] temp = (buf[i].length() + buf[i]).toCharArray();
            temp[0] -= '0';
            //System.out.println(temp);
            String s = String.valueOf(temp);
            //System.out.println(s);
            res += s;
        }
        //System.out.println(res);
        res += '\0';//末尾需要添加 一个0
        return res;
    }

    //对于类型为cname的解析过程
    public static String transfer(byte[] str, byte[] ques) {
        //值得注意的是在域名后面的c016 有事指针，指向dns头部开始的偏移22位
        String res = "";
        short loc = 0, cur = 0;
        int i, j;
        byte[] result;
        for (i = 0; i < str.length; i++) {
            //System.out.println(str[i]);
            if (str[i] < 250 && str[i] > 0) {//域名每个点之间的长度应该不超过
                loc = str[i];
                loc += i;
                for (j = i; j < loc; ++j) {
                    str[j] = str[j + 1];
                    i++;
                }
                //System.out.println("---------->:  " + i);
                str[i] = (byte) '.';
            } else if (str[i] < 0) {//-64 情况下
                //head 长度为
                int pos = str[++i];
                byte[] s = new byte[str.length - 2];
                System.arraycopy(str, 0, s, 0, s.length);
                byte[] foot = new byte[ques.length - pos + 12];
                System.arraycopy(ques, pos - 12, foot, 0, foot.length);
                result = byteMergerAll(s, foot);
                /*System.out.println(byte2hex(result));
                System.out.println(bytetoSting(result));*/
                return bytetoSting(result);
            } else {
                continue;
            }
        }
        return bytetoSting(str);
    }


    //对于A类型的额解析
    public static String getAddr(byte[] str) {
        /*
         * 对于ipv4地址来说总是占最后四个字节的
         * */
        return (str[0] & 0xff) + "." + (str[1] & 0xff) + "." + (str[2] & 0xff) + "." + (str[3] & 0xff);
    }

    //对于AAAA类型的额解析
    public static String getAddr6(byte[] b) {
        /*
         * 对于ipv6地址来说总是占最后16个字节的 ---> IPv6地址是由128位分为8个16位的块。
         * */
        String addr1 = helpaddr6(b[0], b[1]) + ":";
        String addr2 = helpaddr6(b[2], b[3]) + ":";
        String addr3 = helpaddr6(b[4], b[5]) + ":";
        String addr4 = helpaddr6(b[6], b[7]) + ":";

        String addr5 = helpaddr6(b[8], b[9]) + ":";
        String addr6 = helpaddr6(b[10], b[11]) + ":";
        String addr7 = helpaddr6(b[12], b[13]) + ":";
        String addr8 = helpaddr6(b[14], b[15]);
        return addr1 + addr2 + addr3 + addr4 + addr5 + addr6 + addr7 + addr8;
    }

    public static String helpaddr6(byte a, byte b) {
        //辅助ipv6 地址转换
        String res = "";
        if (a != 0) res += byte2hex(a);
        if (b != 0) res += byte2hex(b);
        return res;
    }

    public static String byte2hex(byte b) {
        String hs = "";
        String stmp = "";
        stmp = (Integer.toHexString(b & 0XFF));
        if (stmp.length() == 1)
            hs = hs + "0" + stmp;
        else
            hs = hs + stmp;
        return hs;
    }

    //查询域名服务器 对于迭代查询的过程中还需要对NS进行解析
    public static String trandNs(byte[] src, byte[] all) {
        String res = "";
        short loc = 0, cur = 0;
        int i, j, t;
        byte[] result;
        int len = src.length;
        byte[] s = new byte[100];
        int flag = 0;
        System.out.println(len + "    原始：" + byte2hex(src));
        for (i = 0; i < len; i++) {
            if (src[i] < 250 && src[i] > 0) {//域名每个点之间的长度应该不超过
                loc = src[i];
                loc += i;
                for (j = i; j < loc && j < len; ++j) {
                    s[j] = src[j + 1];
                    i++;
                }
                if (i < len - 2) {
                    s[i] = (byte) '.';
                }
            } else if (src[i] == -64) {//-64 情况下
                //head 长度为 采用偏移的方式获取String 的尾部
                int pos = src[i + 1];
                //部分的值
                for (t = 0; ; ++t, ++pos) {
                    if (all[pos] != 0) //all[pos] !=0
                        s[i + t] = all[pos];
                    else
                        break;
                }
                //result = revfailzero(s);
                result = s;
                len += t - 2; //t 标识新的值
                src = result;
                //System.out.println(len + "    截取：" + byte2hex(src));
                i--; //值得注意的需要对每次操作之应该从前一位开始转换
            } else {
                s[i] = src[i];
            }
        }
        s[len - 1] = 0;

        return bytetoSting(s);
    }

    public static byte[] revfailzero(byte[] b) {
        int i;
        for (i = b.length - 1; ; i--) {
            if (b[i] != 0)
                break;
        }
        byte[] res = new byte[i + 2];
        System.arraycopy(b, 0, res, 0, res.length);
        return res;
    }

    public static String revfail(String s) {
        int i;
        for (i = s.length() - 1; ; i--) {
            if (s.charAt(i) != 0 && s.charAt(i) != '.')
                break;
        }
        return s.substring(0, i + 1);
    }

    public static String byte2hex(byte[] b) { // 二进制转字符串
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = (Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1)
                hs = hs + "0" + stmp;
            else
                hs = hs + stmp;
        }
        return hs;
    }

    public static byte[] hex2byte(String str) { // 字符串转二进制
        if (str == null)
            return null;
        str = str.trim();
        int len = str.length();
        if (len == 0 || len % 2 == 1)
            return null;

        byte[] b = new byte[len / 2];
        try {
            for (int i = 0; i < str.length(); i += 2) {
                b[i / 2] = (byte) Integer
                        .decode("0x" + str.substring(i, i + 2)).intValue();
            }
            return b;
        } catch (Exception e) {
            return null;
        }
    }


    public static String bytetoSting(byte[] msg) {
        String encoded = android.util.Base64.encodeToString(msg, android.util.Base64.DEFAULT);
        //Base64 Decoded
        byte[] decoded = android.util.Base64.decode(encoded, android.util.Base64.DEFAULT);
        return (new String(decoded));
    }

    public static int getunvarLen(int namelen) {
        return namelen + 5;//5 RR 中的常量所占的长度
    }

   /* public static byte[] cutbytes(byte[] src,){
        System.arraycopy(src,srcPos,);
    }
    */


    public static byte[] byteMergerAll(byte[]... values) {
        int length_byte = 0;
        for (int i = 0; i < values.length; i++) {
            length_byte += values[i].length;
        }
        byte[] all_byte = new byte[length_byte];
        int countLength = 0;
        for (int i = 0; i < values.length; i++) {
            byte[] b = values[i];
            System.arraycopy(b, 0, all_byte, countLength, b.length);
            countLength += b.length;
        }
        return all_byte;
    }

    public static byte[] shortToBytes(short n) {
        byte[] b = new byte[2];
        b[1] = (byte) (n & 0xff);
        b[0] = (byte) ((n >> 8) & 0xff);
        return b;
    }

    public static short byteCattoShort(byte[] b) {
        /*
         * 1.byte[0] &0xff << 8
         * 移动后则是0000 0000 0000 0000
         * 2.byte[1] &0xff
         * 则是0000 0000 0101 1010
         * 3. byte[0] | byte[1]
         * */
        return (short) (((b[0] & 0x00FF) << 8) | (0x00FF & b[1]));
    }

    public static int byteCattoInt(byte[] b) {
        return b[3] & 0xFF |
                (b[2] & 0xFF) << 8 |
                (b[1] & 0xFF) << 16 |
                (b[0] & 0xFF) << 24;
    }

    public static byte[] intToByteArray(int a) {
        return new byte[]{
                (byte) ((a >> 24) & 0xFF),
                (byte) ((a >> 16) & 0xFF),
                (byte) ((a >> 8) & 0xFF),
                (byte) (a & 0xFF)
        };
    }


}
