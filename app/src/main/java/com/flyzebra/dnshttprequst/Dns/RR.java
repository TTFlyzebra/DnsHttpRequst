package com.flyzebra.dnshttprequst.Dns;

import com.flyzebra.dnshttprequst.util.Util;

public class RR { //主要应用于dns 服务器返回的数据的提取
    private short Name;//域名 正常情况下 常使用: C00C
    /*
        * 域名（2字节或不定长）：它的格式和Queries区域的查询名字字段是一样的。
        * 有一点不同就是，当报文中域名重复出现的时候，该字段使用2个字节的偏移指针来表示。
        * 比如，在资源记录中，域名通常是查询问题部分的域名的重复，因此用2字节的指针来表示，
        * 具体格式是最前面的两个高位是 11，用于识别指针。其余的14位从DNS报文的开始处计数（从0开始），
        * 指出该报文中的相应字节数。一个典型的例子，C00C(1100000000001100，12正好是头部的长度，
        * 其正好指向Queries区域的查询名字字段)。
    * */

    private short Type;//类型
    private short RRClass;//查询类
    private int ttl;//4个字节 生存时间
    private short Datalength;//数据长度
    private String Data; //最后的数据去 可能包含Address ，Name server , AAAA address ....

    public RR(short name, short type, short RRClass, int ttl, short datalength, String data) {
        Name = name;
        Type = type;
        this.RRClass = RRClass;
        this.ttl = ttl;
        Datalength = datalength;
        Data = data;
    }

    public String printsiminfo(){
        String res = Util.getKey(Type) +": \t " + Data +"\n";
        return res;
    }

    public RR(byte[] rr){
        //通过相应数据对 生成相对应的类
        Name = Util.byteCattoShort(new byte[]{rr[0],rr[1]});;
        Type = Util.byteCattoShort(new byte[]{rr[2],rr[3]});
        this.RRClass = Util.byteCattoShort(new byte[]{rr[4],rr[5]});
        this.ttl = Util.byteCattoInt(new byte[]{rr[6],rr[7],rr[8],rr[9]});
        Datalength = Util.byteCattoShort(new byte[]{rr[10],rr[11]});
        Data = null;
    }

    public byte[] getinfoByte(){
        byte[] name = Util.shortToBytes(Name);
        byte[] type = Util.shortToBytes(Type);
        byte[] rrclass = Util.shortToBytes(RRClass);
        byte[] TTl =Util.intToByteArray(ttl);
        byte[] len = Util.shortToBytes(Datalength);
        return Util.byteMergerAll(name,type,rrclass,TTl,len);
    }

    public String getInfofromData(){
        return null;
    }

    public short getName() {
        return Name;
    }

    public void setName(short name) {
        Name = name;
    }

    public short getType() {
        return Type;
    }

    public void setType(short type) {
        Type = type;
    }

    public short getRRClass() {
        return RRClass;
    }

    public void setRRClass(short RRClass) {
        this.RRClass = RRClass;
    }

    public int getTtl() {
        return ttl;
    }

    public void setTtl(int ttl) {
        this.ttl = ttl;
    }

    public short getDatalength() {
        return Datalength;
    }

    public void setDatalength(short datalength) {
        Datalength = datalength;
    }

    public String getData() {
        return Data;
    }

    public void setData(String data) {
        Data = data;
    }
}
