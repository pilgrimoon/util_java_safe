package org.yangjie.signature;
import java.io.*;
import java.security.*;
import java.util.*;

import static org.yangjie.signature.DSAUtil.genKeyPair;
import static org.yangjie.signature.DSAUtil.sign;

public class PdfHideUtil {
    public PdfHideUtil() throws Exception {
    }

    /**
     * 要求:把获取的数字签名 公钥 时间戳以某个结构转化为二进制信息存储在pdf尾部
     */

    /**
     * 读取二进制pdf文件
     *
     * @param filepath
     */
    public static void readBinaryFile(String filepath) {
        try {
            //建立链接
            FileInputStream fileInputStream = new FileInputStream(filepath);
            int n = 0;
            ArrayList sBuffer = new ArrayList();
            while (n != -1)  //当n不等于-1,则代表未到末尾
            {
                n = fileInputStream.read();//读取文件的一个字节(8个二进制位),并将其由二进制转成十进制的整数返回
                sBuffer.add((byte) n);
            }
            Iterator iter = sBuffer.iterator();
            while (iter.hasNext()) {
                System.out.printf("%02x ", iter.next());
            }
        } catch (FileNotFoundException e) {
            System.out.println("文件不存在或者文件不可读或者文件是目录");
        } catch (IOException e) {
            System.out.println("读取过程存在异常");
        }

    }


    /**
     * pdf尾部写入签名信息
     *
     * @param filepath
     * @param hiddenMessage
     */
    public static void writeHiddenMessage(String filepath, String hiddenMessage) {
        try {
            FileOutputStream outputStream = new FileOutputStream(filepath, true);
            byte[] data = hiddenMessage.getBytes(); //string转byte形式
            outputStream.write(data);
            outputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     * pdf尾部写入签名信息
     *
     * @param filepath
     * @param hiddenMessage
     */
    public static void writebinaryFile(String filepath, HiddenMessage hiddenMessage) {
        try {
            FileOutputStream outputStream = new FileOutputStream(filepath, true);
            byte[] data = hiddenMessage.toString().getBytes(); //string转byte形式
            outputStream.write(data);
            outputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 提取并还原信息
     *
     * @param filepath
     * @return
     */
    public static String extractbinaryFile(String filepath) {
        ArrayList<Byte> eBuffer = new ArrayList<>();
        ArrayList<Byte> originBuffer = new ArrayList<>();

        try {
            //建立链接
            FileInputStream fileInputStream = new FileInputStream(filepath);
            int n = 0;
            //匹配到尾部字节后读取之后的16进制数据
            ArrayList<Byte> sBuffer = new ArrayList();
            while (n != -1) {
                n = fileInputStream.read();//读取文件的一个字节(8个二进制位),并将其由二进制转成十进制的整数返回
                sBuffer.add((byte) n);
            }
            boolean flag = false;
            byte a = 10;
            byte b = 37;
            byte c = 37;
            byte d = 69;
            byte e = 79;
            byte f = 70;
            byte g = 10;
            byte h = -1;
            for (int i = 0; i < sBuffer.size() - 1; i++) {
                if (flag == false && i < sBuffer.size() - 7 && sBuffer.get(i).equals(a)
                        && sBuffer.get(i + 1).equals(b) && sBuffer.get(i + 2).equals(c)
                        && sBuffer.get(i + 3).equals(d) && sBuffer.get(i + 4).equals(e)
                        && sBuffer.get(i + 5).equals(f) && sBuffer.get(i + 6).equals(g)) {
                    flag = true;
                    i += 7;
                }

                if (flag == true) {
                    eBuffer.add((byte) sBuffer.get(i));
                }
                //获取尾部前的全部数据
                if (flag == false) {
                    originBuffer.add((byte) sBuffer.get(i));
                }
            }

            originBuffer.add(a);
            originBuffer.add(b);
            originBuffer.add(c);
            originBuffer.add(d);
            originBuffer.add(e);
            originBuffer.add(f);
            originBuffer.add(g);

            try {
                FileOutputStream outputStream = new FileOutputStream(filepath, false);
                byte[] ByteOriginBuffer = new byte[originBuffer.size()];
                for (int i = 0; i < originBuffer.size(); i++) {
                    ByteOriginBuffer[i] = originBuffer.get(i);
                }
                outputStream.write(ByteOriginBuffer);
                outputStream.close();
            } catch (FileNotFoundException e1) {
                e1.printStackTrace();
            } catch (IOException e1) {
                e1.printStackTrace();
            }

            // 如果有修改过就返回数据
            if (flag == true) {
                byte[] bytes = new byte[eBuffer.size()];
                for (int i = 0; i < eBuffer.size(); i++) {
                    bytes[i] = eBuffer.get(i);
                }
                String strContent = "";
                strContent = new String(bytes, "utf-8");
                return strContent;
            }
        } catch (FileNotFoundException e) {
            System.out.println("文件不存在或者文件不可读或者文件是目录");
        } catch (IOException e) {
            System.out.println("读取过程存在异常");
        }
        return null;
    }

    /**
     * 更新信息前清除尾部信息
     *
     * @param filepath
     */
    public static void clearBinaryFile(String filepath) {
        ArrayList<Byte> eBuffer = new ArrayList<>();
        ArrayList<Byte> originBuffer = new ArrayList<>();

        try {
            //建立链接
            FileInputStream fileInputStream = new FileInputStream(filepath);
            int n = 0;
            //匹配到尾部字节后读取之后的16进制数据
            ArrayList<Byte> sBuffer = new ArrayList();
            while (n != -1) {
                n = fileInputStream.read();//读取文件的一个字节(8个二进制位),并将其由二进制转成十进制的整数返回
                sBuffer.add((byte) n);
            }
            boolean flag = false;

            byte a = 10;
            byte b = 37;
            byte c = 37;
            byte d = 69;
            byte e = 79;
            byte f = 70;
            byte g = 10;
            byte h = -1;
            for (int i = 0; i < sBuffer.size() - 1; i++) {
                if (flag == false && i < sBuffer.size() - 7 && sBuffer.get(i).equals(a)
                        && sBuffer.get(i + 1).equals(b) && sBuffer.get(i + 2).equals(c)
                        && sBuffer.get(i + 3).equals(d) && sBuffer.get(i + 4).equals(e)
                        && sBuffer.get(i + 5).equals(f) && sBuffer.get(i + 6).equals(g)) {
                    flag = true;
                    i += 7;
                }

                if (flag == true) {
                    eBuffer.add((byte) sBuffer.get(i));
                }
                //获取尾部前的全部数据
                if (flag == false) {
                    originBuffer.add((byte) sBuffer.get(i));
                }
            }

            originBuffer.add(a);
            originBuffer.add(b);
            originBuffer.add(c);
            originBuffer.add(d);
            originBuffer.add(e);
            originBuffer.add(f);
            originBuffer.add(g);


            try {
                FileOutputStream outputStream = new FileOutputStream(filepath, false);
                byte[] ByteOriginBuffer = new byte[originBuffer.size()];
                for (int i = 0; i < originBuffer.size(); i++) {
                    ByteOriginBuffer[i] = originBuffer.get(i);
                }
                outputStream.write(ByteOriginBuffer);
                outputStream.close();
            } catch (FileNotFoundException e1) {
                e1.printStackTrace();
            } catch (IOException e1) {
                e1.printStackTrace();
            }

            // 如果有修改过就返回数据
            if (flag == true) {
                byte[] bytes = new byte[eBuffer.size()];
                for (int i = 0; i < eBuffer.size(); i++) {
                    bytes[i] = eBuffer.get(i);
                }
                String strContent = "";
                strContent = new String(bytes, "utf-8");
            }
        } catch (FileNotFoundException e) {
            System.out.println("文件不存在或者文件不可读或者文件是目录");
        } catch (IOException e) {
            System.out.println("读取过程存在异常");
        }
    }


    public static String getsign(String message) {
        String splitMessage[] = message.split(",");
        return splitMessage[0];
    }

    public static String getusername(String message) {
        String splitMessage[] = message.split(",");
        return splitMessage[1];
    }

    public static String getdate(String message) {
        String splitMessage[] = message.split(",");
        return splitMessage[2];
    }

    public static void main(String[] args) throws Exception {
        String filePath = "C:/Users/ASUS/Desktop/document.pdf";
        KeyPair keyPair = genKeyPair(); //生成一组keypair
        String username = "test_user";
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        Date date = new Date();
        String sign = sign(filePath, privateKey);
        HiddenMessage hiddenMessage = new HiddenMessage(sign, username, date, "other information here");
        String splitMessage[] = hiddenMessage.toString().split(",");
        readBinaryFile(filePath);
        writebinaryFile(filePath, hiddenMessage);
        String Message = "," + "operation:download";
        writeHiddenMessage(filePath, Message);
        String extractionMessage = extractbinaryFile(filePath);
        clearBinaryFile(filePath);
        System.out.println();
        System.out.println("提取到的数据为:" + extractionMessage);
        System.out.println(getsign(extractionMessage));
        System.out.println(getusername(extractionMessage));
        System.out.println(getdate(extractionMessage));
    }

}
