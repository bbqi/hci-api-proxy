package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "encoding/hex"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "math/big"
    "net"
    "net/http"
    "net/http/httputil"
    "net/url"
    "os"
    "strings"
    "time"

    "gopkg.in/yaml.v2"
)

var csrf string
var ticket string
var config Config

type Config struct {
    API    API
    Server Server
}

type API struct {
    Host     string
    User     string
    Password string
    Timeout  string
    PassHash string
}

type Server struct {
    Addr  string
    Check bool
}

type PubkeyResp struct {
    Success int    `json:"success"`
    Data    string `json:"data"`
}

type TicketResp struct {
    Success int        `json:"success"`
    Data    TicketData `json:"data"`
}
type Dc struct {
}
type Access struct {
}
type Nodes struct {
}
type Vms struct {
    VMGroup          int `json:"VM.Group"`
    VMEdit           int `json:"VM.Edit"`
    VMEncrypt        int `json:"VM.Encrypt"`
    VMConsole        int `json:"VM.Console"`
    VMTagManage      int `json:"VM.Tag.Manage"`
    VMMigrate        int `json:"VM.Migrate"`
    VMDelete         int `json:"VM.Delete"`
    VMPower          int `json:"VM.Power"`
    VMClone          int `json:"VM.Clone"`
    VMTemplate       int `json:"VM.Template"`
    VMExport         int `json:"VM.Export"`
    VMCreate         int `json:"VM.Create"`
    VMSnapshotbackup int `json:"VM.SnapshotBackup"`
    VMTagAllocate    int `json:"VM.Tag.Allocate"`
}
type Storage struct {
    StorageDelete int `json:"Storage.Delete"`
    StorageUse    int `json:"Storage.Use"`
}
type Cap struct {
    Dc      Dc      `json:"dc"`
    Access  Access  `json:"access"`
    Nodes   Nodes   `json:"nodes"`
    Vms     Vms     `json:"vms"`
    Storage Storage `json:"storage"`
}
type TicketData struct {
    Cap                 Cap    `json:"cap"`
    Cluster             string `json:"cluster"`
    UserRole            string `json:"user_role"`
    PasswordType        string `json:"password_type"`
    PasswordStatus      string `json:"password_status"`
    DefaultIP           int    `json:"default_ip"`
    Username            string `json:"username"`
    ClientIP            string `json:"client_ip"`
    CsrfPreventionToken string `json:"CSRFPreventionToken"`
    Istowelcome         int    `json:"isToWelcome"`
    PasswordRemainDays  int    `json:"password_remain_days"`
    Ticket              string `json:"ticket"`
}

/*type ReverseProxy struct {
    // Director must be a function which modifies
    // the request into a new request to be sent
    // using Transport. Its response is then copied
    // back to the original client unmodified.
    // Director must not access the provided Request
    // after returning.

    Director func(*http.Request)
    Transport http.RoundTripper
    FlushInterval time.Duration
    ErrorLog *log.Logger
    BufferPool BufferPool
    ModifyResponse func(*http.Response) error
    ErrorHandler func(http.ResponseWriter, *http.Request, error)
}*/

func NewHostReverseProxy(target *url.URL) *httputil.ReverseProxy {

    director := func(req *http.Request) {
        //target := targets[rand.Int()%len(targets)]
        req.URL.Scheme = target.Scheme
        req.URL.Host = target.Host
        //req.URL.Path = target.Path

        //fmt.Println("target.Path:", target.Path)

        // 若"User-Agent" 这个header不存在，则置空
        if _, ok := req.Header["Cookie"]; !ok {
            // explicitly disable User-Agent so it's not set to default value
            req.Header.Set("Cookie", "LoginAuthCookie="+ticket)
            req.Header.Set("CSRFPreventionToken", csrf)
        }
    }

    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
    }

    modresp := func(resp *http.Response) error {
        fmt.Println(" -", resp.StatusCode)
        if resp.StatusCode == 401 {
            RenewTicket()
        }
        return nil
    }
    return &httputil.ReverseProxy{Director: director, Transport: tr, ModifyResponse: modresp}
}

//将request转发给 http://127.0.0.1:2003 https://192.168.x.x/vapi/json/access/ticket
func helloHandler(w http.ResponseWriter, r *http.Request) {
    //真是HCI api地址
    trueServer := "https://192.168.x.x"

    url, err := url.Parse(trueServer)
    if err != nil {
        log.Println(err)
        return
    }
    fmt.Printf("REQUEST: %s", r.URL)
    //proxy := httputil.NewSingleHostReverseProxy(url)
    proxy := NewHostReverseProxy(url)
    proxy.ServeHTTP(w, r)

}

func checkPortStatus(host string) error {
    port := "443"
    timeout := 3 * time.Second
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
    defer conn.Close()
    if err != nil {

        return err
    }
    if conn == nil {
        return errors.New("Can't Connect")
    }
    return nil
}

func getPublicKey(host string) string {
    url := "https://" + host + "/vapi/json/public_key"

    js := HttpRequest("GET", url, "")

    var pk_resp PubkeyResp
    err := json.Unmarshal(js, &pk_resp)
    if err != nil {
        fmt.Println("error:", err)
        return ""
    }
    return pk_resp.Data
}

func calcPassHash(host string, password string) string {
    N := getPublicKey(host)
    if N == "" {
        log.Fatal("Get PublicKey failed")
        return ""
    }

    E := 0x10001
    bigN := new(big.Int)
    _, ok := bigN.SetString(N, 16)
    if !ok {
        panic("failed to parse")
    }
    pub := rsa.PublicKey{
        N: bigN,
        E: E,
    }
    cc, _ := rsa.EncryptPKCS1v15(rand.Reader, &pub, []byte(password))
    return hex.EncodeToString(cc)
}

func getTicket(host string, token string) (string, string) {
    url := "https://" + host + "/vapi/json/access/ticket"

    data := "username=admin&password=" + token

    js := HttpRequest("POST", url, data)

    var tk_resp TicketResp
    err := json.Unmarshal(js, &tk_resp)
    if err != nil {
        fmt.Println("error:", err)
        return "", ""
    }

    return tk_resp.Data.CsrfPreventionToken, tk_resp.Data.Ticket
}

func HttpRequest(method string, url string, data string) []byte {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
    }

    client := &http.Client{Transport: tr}
    var req *http.Request

    req, _ = http.NewRequest(method, url, strings.NewReader(data))

    req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36 QIHU 360SE")

    resp, err := client.Do(req)

    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    b, _ := ioutil.ReadAll(resp.Body)
    return b
}

func RenewTicket() {
    pwdhash := calcPassHash(config.API.Host, config.API.Password)
    csrf, ticket = getTicket(config.API.Host, pwdhash)
    if ticket == "" {
        log.Fatal("Get Ticket failed.")
        //os.Exit(0)
    }
}

func LoadConfig() {
    configyaml := flag.String("f", "config.yaml", "Path to config.")
    h := flag.Bool("h", false, "show help")
    //flag.Usage = usage
    flag.Parse()

    if *h {
        flag.Usage()
        os.Exit(0)
    }

    file, err := ioutil.ReadFile(*configyaml)
    if err != nil {
        log.Fatal(err)
    }
    err = yaml.Unmarshal(file, &config)
    if err != nil {
        log.Fatal("Problem parsing config: ", err)
    }

}

func main() {

    LoadConfig()

    if config.Server.Check {
        err := checkPortStatus(config.API.Host)
        if err != nil {
            log.Fatal("Can't connect api. Please check network or config file.")
            os.Exit(0)
        }
    }

    RenewTicket()

    http.HandleFunc("/", helloHandler)
    fmt.Println("Start Server :", config.Server.Addr)
    log.Fatal(http.ListenAndServe(config.Server.Addr, nil))
}
