package com.flyzebra.dnshttprequst.Dns;

import com.flyzebra.dnshttprequst.util.Util;

public class Head {
    //dns 报文的头部定义 可直接使用十六进制赋值 12byte
    private short TransactionID;
    private short Flags; //对于每次请求dns服务器时 0x0100
    /*  QR（1bit）	查询/响应标志，0为查询，1为响应
        opcode（4bit）	0表示标准查询，1表示反向查询，2表示服务器状态请求
        AA（1bit）	表示授权回答
        TC（1bit）	表示可截断的
        RD（1bit）	表示期望递归
        RA（1bit）	表示可用递归
        zero (3bit)  空值
        rcode（4bit）	表示返回码，0表示没有差错，3表示名字差错，2表示服务器错误（Server Failure）
     */
    private short Questions;
    private short AnswerRRs;
    private  short AuthorityRRs;
    private short AddtitionalRRs;

    public Head(short transactionID, short flags, short questions, short answerRRs, short authorityRRs, short addtitionalRRs) {
        TransactionID = transactionID;
        Flags = flags;
        Questions = questions;
        AnswerRRs = answerRRs;
        AuthorityRRs = authorityRRs;
        AddtitionalRRs = addtitionalRRs;
    }

    public Head(byte[] head){
        //实现构造方法直接通过byte[] 生成相应的头部
        TransactionID = Util.byteCattoShort(new byte[]{head[0],head[1]});
        Flags = Util.byteCattoShort(new byte[]{head[2],head[3]});
        Questions = Util.byteCattoShort(new byte[]{head[4],head[5]});
        AnswerRRs = Util.byteCattoShort(new byte[]{head[6],head[7]});
        AuthorityRRs = Util.byteCattoShort(new byte[]{head[8],head[9]});
        AddtitionalRRs = Util.byteCattoShort(new byte[]{head[10],head[11]});
    }

    public byte[] getHead(){
        //获得头部的 byte[]
        byte[] t1 = Util.shortToBytes(TransactionID);
        byte[] t2 = Util.shortToBytes(Flags);
        byte[] t3 = Util.shortToBytes(Questions);
        byte[] t4 = Util.shortToBytes(AnswerRRs);
        byte[] t5 = Util.shortToBytes(AuthorityRRs);
        byte[] t6 = Util.shortToBytes(AddtitionalRRs);

        return Util.byteMergerAll(t1,t2,t3,t4,t5,t6);
    }

    public short getTransactionID() {
        return TransactionID;
    }

    public void setTransactionID(short transactionID) {
        TransactionID = transactionID;
    }

    public short getFlags() {
        return Flags;
    }

    public void setFlags(short flags) {
        Flags = flags;
    }

    public short getQuestions() {
        return Questions;
    }

    public void setQuestions(short questions) {
        Questions = questions;
    }

    public short getAnswerRRs() {
        return AnswerRRs;
    }

    public void setAnswerRRs(short answerRRs) {
        AnswerRRs = answerRRs;
    }

    public short getAuthorityRRs() {
        return AuthorityRRs;
    }

    public void setAuthorityRRs(short authorityRRs) {
        AuthorityRRs = authorityRRs;
    }

    public short getAddtitionalRRs() {
        return AddtitionalRRs;
    }

    public void setAddtitionalRRs(short addtitionalRRs) {
        AddtitionalRRs = addtitionalRRs;
    }
}
