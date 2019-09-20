package com.flyzebra.dnshttprequst.Dns;

import com.flyzebra.dnshttprequst.util.Util;

public class Dnsdefine {
    private Head head;
    private Queries queries;
    //RR
    private RR[] AnswerRRs;
    private RR[] AuthorityRRs;
    private RR[] AddtitionalRRs;

    public Dnsdefine(Head head, Queries queries, RR[] answerRRs, RR[] authorityRRs, RR[] addtitionalRRs) {
        this.head = head;
        this.queries = queries;
        AnswerRRs = answerRRs;
        AuthorityRRs = authorityRRs;
        AddtitionalRRs = addtitionalRRs;
    }

    public Dnsdefine(Head head, Queries queries){
        this.head = head;
        this.queries = queries;
        AnswerRRs = null;
        AuthorityRRs = null;
        AddtitionalRRs = null;
    }

    @Override
    public String toString() {
        //通过重写该方法实现对获取到的信息打印为字符串
        return null;
    }

    public byte[] Sendmsgbyte(){
        byte[] h = head.getHead();
        byte[] q = queries.getQueries();
        return Util.byteMergerAll(h,q);
    }

    public String  printfinfo(){
        //输出请求得到的报文的相关信息
        String res = "\n";
        res += "Questions:    " + head.getQuestions() + "\n";
        res += "AnswerRRs:    " + head.getAnswerRRs() + "\n";
        res += "AuthorityRRs:    " + head.getAuthorityRRs() + "\n";
        res += "AddtitionalRRs:    " + head.getAddtitionalRRs() + "\n";
        if (AnswerRRs != null){
            res +="AnswerRRs:\n";
            for (int i = 0; i< AnswerRRs.length ;i++)
                res += i +":    " + AnswerRRs[i].printsiminfo();
        }
        if (AuthorityRRs != null){
            res += "AuthorityRRs:\n";
            for (int i = 0; i< AuthorityRRs.length ;i++)
                res += i +":    " +AuthorityRRs[i].printsiminfo();
        }
        if (AddtitionalRRs != null){
            res += "AddtitionalRRs\n";
            for (int i = 0; i< AddtitionalRRs.length ;i++)
                res +=  i +":    " + AddtitionalRRs[i].printsiminfo();
        }
        return res;
    }

    public Head getHead() {
        return head;
    }

    public void setHead(Head head) {
        this.head = head;
    }

    public Queries getQueries() {
        return queries;
    }

    public void setQueries(Queries queries) {
        this.queries = queries;
    }

    public RR[] getAnswerRRs() {
        return AnswerRRs;
    }

    public void setAnswerRRs(RR[] answerRRs) {
        AnswerRRs = answerRRs;
    }

    public RR[] getAuthorityRRs() {
        return AuthorityRRs;
    }

    public void setAuthorityRRs(RR[] authorityRRs) {
        AuthorityRRs = authorityRRs;
    }

    public RR[] getAddtitionalRRs() {
        return AddtitionalRRs;
    }

    public void setAddtitionalRRs(RR[] addtitionalRRs) {
        AddtitionalRRs = addtitionalRRs;
    }
}
