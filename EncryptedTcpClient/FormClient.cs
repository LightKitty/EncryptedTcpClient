using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace EncryptedTcpClient
{
    public partial class FormClient : Form
    {
        private bool isExit = false;
        private delegate void SetListBoxCallback(string str);
        private SetListBoxCallback setListBoxCallback;
        private TcpClient client;
        private BinaryReader br;
        private BinaryWriter bw;
        //对称加密
        private TripleDESCryptoServiceProvider tdes;
        //不对称加密
        private RSACryptoServiceProvider rsa;
        public FormClient()
        {
            InitializeComponent();
            listBoxStatus.HorizontalScrollbar = true;
            setListBoxCallback = new SetListBoxCallback(SetListBox);
        }

        private void buttonConnect_Click(object sender, EventArgs e)
        {
            try
            {
                //实际使用时要将Dns.GetHostName()改为服务器域名
                client = new TcpClient(Dns.GetHostName(), 51888);
                SetListBox(string.Format("本机EndPoint：{0}", client.Client.LocalEndPoint));
                SetListBox("与服务器建立连接成功");
            }
            catch
            {
                SetListBox("与服务器连接失败");
                return;
            }
            buttonConnect.Enabled = false;
            //获取网络流
            NetworkStream networkStream = client.GetStream();
            //将网络流作为二进制读写对象
            br = new BinaryReader(networkStream);
            bw = new BinaryWriter(networkStream);
            Thread threadReceive = new Thread(new ThreadStart(ReceiveData));
            threadReceive.Start();
            //使用默认密钥创建对称加密对象
            tdes = new TripleDESCryptoServiceProvider();
            //使用默认密钥创建不对称加密对象
            rsa = new RSACryptoServiceProvider();
            //导出不对称加密密钥的xml 表示形式，false 表示不包括私钥
            string rsaPublicKey = rsa.ToXmlString(false);
            //将导出的公钥发送到服务器，公钥可以对任何人公开
            SendData("rsaPublicKey,true", Encoding.Default.GetBytes(rsaPublicKey));
        }

        //接收线程
        private void ReceiveData()
        {
            while (isExit == false)
            {
                //保存接收的命令字符串
                string receiveString = null;
                //解析命令用
                //每条命令均带有一个参数，值为true 或者false，表示是否有紧跟的字节数组
                string[] splitString = null;
                byte[] receiveBytes = null;
                try
                {
                    //从网络流中读出命令字符串
                    //此方法会自动判断字符串长度前缀，并根据长度前缀读出字符串
                    receiveString = br.ReadString();
                    splitString = receiveString.Split(',');
                    if (splitString[1] == "true")
                    {
                        //先从网络流中读出32 位的长度前缀
                        int bytesLength = br.ReadInt32();
                        //然后读出指定长度的内容保存到字节数组中
                        receiveBytes = br.ReadBytes(bytesLength);
                    }
                }
                catch
                {
                    //底层套接字不存在时会出现异常
                    SetListBox("接收数据失败");
                }
                if (receiveString == null)
                {
                    if (isExit == false)
                    {
                        MessageBox.Show("与服务器失去联系！");
                    }
                    break;
                }
                SetListBox("收到：" + receiveString);
                if (receiveBytes != null)
                {
                    SetListBox(string.Format("收到：{0}",
                    Encoding.Default.GetString(receiveBytes)));
                }
                switch (splitString[0])
                {
                    case "Talk":
                        //解密
                        string talkString = DecryptText(receiveBytes, tdes.Key, tdes.IV);
                        if (talkString != null)
                        {
                            SetListBox(string.Format("服务器说：{0}", talkString));
                        }
                        break;
                    case "tdesKey":
                        //解密
                        tdes.Key = rsa.Decrypt(receiveBytes, false);
                        break;
                    case "tdesIV":
                        //解密
                        tdes.IV = rsa.Decrypt(receiveBytes, false);
                        break;
                    default:
                        SetListBox("什么意思啊：" + receiveString);
                        break;
                }
            }
            Application.Exit();
        }

        //使用对称加密加密字符串
        private byte[] EncryptText(string str, byte[] Key, byte[] IV)
        {
            //创建一个内存流
            MemoryStream memoryStream = new MemoryStream();
            //使用传递的私钥和IV 创建加密流
            CryptoStream cryptoStream = new CryptoStream(memoryStream,
            new TripleDESCryptoServiceProvider().CreateEncryptor(Key, IV),
            CryptoStreamMode.Write);
            //将传递的字符串转换为字节数组
            byte[] toEncrypt = Encoding.UTF8.GetBytes(str);
            try
            {
                //将字节数组写入加密流,并清除缓冲区
                cryptoStream.Write(toEncrypt, 0, toEncrypt.Length);
                cryptoStream.FlushFinalBlock();
                //得到加密后的字节数组
                byte[] encryptedBytes = memoryStream.ToArray();
                return encryptedBytes;
            }
            catch (CryptographicException err)
            {
                SetListBox("加密出错：" + err.Message);
                return null;
            }
            finally
            {
                cryptoStream.Close();
                memoryStream.Close();
            }
        }

        //使用对称加密算法解密接收的字符串
        private string DecryptText(byte[] dataBytes, byte[] Key, byte[] IV)
        {
            //根据加密后的字节数组创建一个内存流
            MemoryStream memoryStream = new MemoryStream(dataBytes);
            //使用传递的私钥、IV 和内存流创建解密流
            CryptoStream cryptoStream = new CryptoStream(memoryStream,
            new TripleDESCryptoServiceProvider().CreateDecryptor(Key, IV),
            CryptoStreamMode.Read);
            //创建一个字节数组保存解密后的数据
            byte[] decryptBytes = new byte[dataBytes.Length];
            try
            {
                //从解密流中将解密后的数据读到字节数组中
                cryptoStream.Read(decryptBytes, 0, decryptBytes.Length);
                //得到解密后的字符串
                string decryptedString = Encoding.UTF8.GetString(decryptBytes);
                return decryptedString;
            }
            catch (CryptographicException err)
            {
                SetListBox("解密出错：" + err.Message);
                return null;
            }
            finally
            {
                cryptoStream.Close();
                memoryStream.Close();
            }
        }

        //发送信息到服务器
        private void SendData(string command, byte[] bytes)
        {
            //每条命令均带有一个参数，值为true 或者false，表示是否有紧跟的字节数组
            //如果不带参数，也可以实现，但是会导致接收方判断代码复杂化
            string[] splitCommand = command.Split(',');
            try
            {
                //先将命令字符串写入网络流，此方法会自动附加字符串长度前缀
                bw.Write(command);
                SetListBox(string.Format("发送：{0}", command));
                if (splitCommand[1] == "true")
                {
                    //先将字节数组的长度（32 位整数）写入网络流
                    bw.Write(bytes.Length);
                    //然后将字节数组写入网络流
                    bw.Write(bytes);
                    bw.Flush();
                    SetListBox(string.Format("发送：{0}", Encoding.UTF8.GetString(bytes)));
                    if (splitCommand[0] == "Talk")
                    {
                        SetListBox("加密前内容：" + textBoxSend.Text);
                    }
                }
            }
            catch
            {
                SetListBox("发送失败!");
            }
        }

        private void SetListBox(string str)
        {
            if (listBoxStatus.InvokeRequired == true)
            {
                this.Invoke(setListBoxCallback, str);
            }
            else
            {
                listBoxStatus.Items.Add(str);
                listBoxStatus.SelectedIndex = listBoxStatus.Items.Count - 1;
                listBoxStatus.ClearSelected();
            }
        }

        //单击发送按钮触发的事件
        private void buttonSend_Click(object sender, EventArgs e)
        {
            //加密textBoxSend.Text 的内容
            byte[] encryptedBytes = EncryptText(textBoxSend.Text, tdes.Key, tdes.IV);
            if (encryptedBytes != null)
            {
                SendData("Talk,true", encryptedBytes);
                textBoxSend.Clear();
            }
        }

        private void FormClient_FormClosing(object sender, FormClosingEventArgs e)
        {
            //未与服务器连接前client 为null
            if (client != null)
            {
                SendData("Logout,false", null);
                isExit = true;
                br.Close();
                bw.Close();
                client.Close();
            }
        }

        private void textBoxSend_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)Keys.Return)
            {
                buttonSend_Click(null, null);
            }
        }
    }
}
