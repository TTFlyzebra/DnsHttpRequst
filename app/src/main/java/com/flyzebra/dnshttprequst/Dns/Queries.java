package com.flyzebra.dnshttprequst.Dns;

import com.flyzebra.dnshttprequst.util.Util;

public class Queries {
    private String Name;//需要解析的域名
    private short Type;
    private short Queries_class;

    public Queries(String name, String type) {
        Name = name;
        Type = Util.getType(type);
        Queries_class = 0x0001;//对于网络护具来说可就是0x001 表示Internet data
    }

    public Queries(byte [] que){
        //通过获取到的byte的生成相应的Queries
        //可通过对 byte[] 直接解析出来的对应提问的域名的相关信息
    }

    public int getNameLen(){
        return Util.transfer(Name).getBytes().length;
    }

    public int getLabelCount(){
        String[]  buf = Name.split("\\.");
        return buf.length;
    }

    public byte[] getQueries(){
        byte[] domain = Util.transfer(Name).getBytes();
        byte[] type = Util.shortToBytes(Type);
        byte[] Queclass = Util.shortToBytes(Queries_class);
        return Util.byteMergerAll(domain,type,Queclass);
    }

    public String getName() {
        return Name;
    }

    public void setName(String name) {
        Name = name;
    }

    public short getType() {
        return Type;
    }

    public void setType(short type) {
        Type = type;
    }

    public short getQueries_class() {
        return Queries_class;
    }

    public void setQueries_class(short queries_class) {
        Queries_class = queries_class;
    }
}
