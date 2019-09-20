package com.flyzebra.dnshttprequst.Dns;

import com.flyzebra.dnshttprequst.util.Util;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LocalDnsBuf {
    private String domain;
    private String type;
    private String data;
    private String tll;
    private String separate;



    public LocalDnsBuf(){
        this.separate = " ";
    }

    public LocalDnsBuf(String domain, String type, String data, String tll) {
        this.domain = domain;
        this.type = type;
        this.data = data;
        this.tll = tll;
        this.separate = " ";
    }

    public LocalDnsBuf(String domain, String type, String data){
        this.domain = domain;
        this.type = type;
        this.data = data;
        this.separate = " ";
    }

    public void WirtednsBuf(String domain,String type,String data){
        //每条记录中间使用****分隔
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(Util.filePath,true));
            String str = domain + separate+ type + separate+ data +separate + tll;
            bw.write(str);
            bw.newLine();
            System.out.println("写入："+ str);
            bw.flush();
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void WirtednsBuf(){
        File file = new File(Util.filePath);
        if (!file.exists()){
            //如果文件不存在则创建文件
            try {
                file.createNewFile();
                System.out.println("创建了一个dnsbuf.txt");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        String str = domain + separate+ type + separate+ data +separate + tll;
        try {
            FileWriter fw = new FileWriter(file);
            fw.write(str);
            fw.write("/r/n");//表示换行
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //获取对应的的域名的信息
    public List<Map<String,String>> ReadBuf(String url){

        List<Map<String,String>> list = new ArrayList<>();
        try {
            BufferedReader br  = new BufferedReader(new FileReader(Util.filePath));
            String str = null;
            while((str = br.readLine())!=null){
                Map<String,String> map = new HashMap<>();
                String[] sub = str.split(separate);
                if (url.equals(sub[0])){
                    System.out.println(sub[0] +"     "+sub[1]+":    "+sub[2]);
                    map.put(sub[0],sub[1]+":    "+sub[2]);
                }
               list.add(map);
            }
            br.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return list;
    }

    public String getSeparate() {
        return separate;
    }

    public void setSeparate(String separate) {
        this.separate = separate;
    }


    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getTll() {
        return tll;
    }

    public void setTll(String tll) {
        this.tll = tll;
    }
}
