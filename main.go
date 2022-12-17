package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	localTokenUrl = "/local-ssh/api?method=get"
	routerInfoUrl = "/cgi-bin/turbo/proxy/router_info"
	localSshUrl   = "/local-ssh/api?method=valid&data=%s"
)

const (
	retry       = 10
	sleepSecond = 10 * time.Second
)

type LocalTokenResp struct {
	Data string
}

type LocalSshResp struct {
	Data string
}

type RouterInfoResp struct {
	Data RouterInfoData
}

type RouterInfoData struct {
	Uuid string
}

var ErrorSystemBusy = errors.New("系统忙，请稍后重试")
var address = "192.168.199.1"

func main() {
	var input string
	var n int
	var ip net.IP
	var err error

	for {
		fmtPrint("请输入极路由管理IP，然后按回车继续(不输入则默认192.168.199.1): ")

		n, err = fmt.Scanln(&input)
		if err != nil && err.Error() != "unexpected newline" {
			fmtPrintFln("输入有误，请重新输入: %v", err)
			continue
		}

		if n == 0 {
			input = address
		}

		ip = net.ParseIP(input)
		if ip == nil {
			fmtPrintFln("输入非合法IP，请重新输入")
			continue
		}

		address = ip.String()
		fmtPrintFln("极路由IP为: %s", address)
		break
	}

	launchSsh()

	fmtPrint("按回车退出...")
	_, _ = fmt.Scanln(&input)
}

func launchSsh() {
	var localToken string
	var uuid string
	var cloudToken string
	var port string
	var err error

	for i := 0; i <= retry; i++ {
		if i != 0 {
			time.Sleep(sleepSecond)
			fmtPrintFln("----------------------------------------------------------------")
			fmtPrintFln("第%d次重试", i)
		}

		fmtPrintFln("开始获取UUID")
		uuid, err = getUUID()
		if err != nil {
			fmtPrintFln("获取uuid出错: %v", err)
			continue
		}
		fmtPrintFln("获取uuid成功: %s ", uuid)

		fmtPrintFln("开始获取local_token")
		localToken, err = getLocalToken()
		if err != nil {
			fmtPrintFln("获取local_token出错: %v", err)
			continue
		}
		fmtPrintFln("获取local_token成功: %s", localToken)

		fmtPrintFln("开始生成cloud_token")
		cloudToken, err = getCloudToken(uuid, localToken)
		if err != nil {
			fmtPrintFln("生成cloud_token出错: %v", err)
			continue
		}
		fmtPrintFln("生成cloud_token成功: %s", cloudToken)

		fmtPrintFln("开始获取local_ssh")
		port, err = getLocalSsh(cloudToken)
		if err != nil {
			fmtPrintFln("获取local_ssh出错: %v", err)
			continue
		}
		fmtPrintFln("获取local_ssh成功，端口号: %s，有效期5分钟，请及时更改为永久ssh", port)
		return
	}
	fmtPrintFln("获取local_ssh出错，请检查IP是否有误，UUID，LocalToken是否正常获取")
	fmtPrintFln("极路由IP为: %s", address)
	fmtPrintFln("UUID为: %s", uuid)
	fmtPrintFln("LocalToken为: %s", localToken)
	fmtPrintFln("CloudToken为: %s", cloudToken)
}

func getLocalSsh(cloudToken string) (port string, err error) {
	var osr *LocalSshResp
	osr = &LocalSshResp{}

	err = httpGet(generateUrl(localSshUrl, cloudToken), osr)
	if err != nil {
		return
	}

	if !strings.Contains(osr.Data, "Success: ssh port is ") {
		err = errors.New(fmt.Sprint("Unknown error:", osr.Data))
	}

	port = strings.ReplaceAll(osr.Data, "Success: ssh port is ", "")
	return
}

func getUUID() (uuid string, err error) {
	var rir *RouterInfoResp
	rir = &RouterInfoResp{}

	err = httpGet(generateUrl(routerInfoUrl), rir)
	if err != nil {
		return
	}

	uuid = rir.Data.Uuid
	return
}

func getLocalToken() (localToken string, err error) {
	var ltr *LocalTokenResp
	ltr = &LocalTokenResp{}

	err = httpGet(generateUrl(localTokenUrl), ltr)
	if err != nil {
		return
	}

	localToken = ltr.Data
	return
}

func getCloudToken(uuid, localToken string) (cloudToken string, err error) {
	var key [sha1.Size]byte
	var msg []byte
	var expectedMAC []byte

	msg, err = tokenToMsg(localToken)
	if err != nil {
		return
	}

	key = sha1Sum(uuid)
	expectedMAC = hmacSha1Sum(msg, key[:])
	cloudToken = base64.StdEncoding.EncodeToString(expectedMAC)

	return
}

func httpGet(url string, data interface{}) (err error) {
	var resp *http.Response
	var body []byte

	url = strings.ReplaceAll(url, "+", "%2B")

	resp, err = http.Get(url)
	if err != nil {
		return
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if strings.Contains(string(body), "系统忙，请稍后重试") {
		err = ErrorSystemBusy
		return
	}

	err = json.Unmarshal(body, data)
	if err != nil {
		fmtPrintFln("json Unmarshal error: %s", string(body))
		return
	}

	return
}

func generateUrl(api string, a ...any) (url string) {
	api = fmt.Sprintf(api, a...)
	url = "http://" + address + api
	return
}

func tokenToMsg(localToken string) (msg []byte, err error) {
	var decodedLocalToken []byte
	var splitToken []string
	var timestamp int
	var msgStr string

	decodedLocalToken, err = base64.StdEncoding.DecodeString(localToken)
	if err != nil {
		return
	}
	splitToken = strings.Split(string(decodedLocalToken), ",")

	timestamp, err = strconv.Atoi(splitToken[2])
	if err != nil {
		return
	}

	timestamp += 1
	splitToken[2] = strconv.Itoa(timestamp)
	msgStr = strings.Join(splitToken[:3], ",")
	msg = []byte(msgStr)

	return
}

func sha1Sum(uuid string) (checksum [sha1.Size]byte) {
	var data []byte
	data = []byte(uuid)
	checksum = sha1.Sum(data)
	return
}

func hmacSha1Sum(msg, key []byte) (expectedMAC []byte) {
	var mac hash.Hash
	mac = hmac.New(sha1.New, key)
	mac.Write(msg)
	expectedMAC = mac.Sum(nil)
	return
}

func fmtPrintFln(format string, a ...any) {
	fmt.Printf(format, a...)
	fmt.Println()
}

func fmtPrint(a ...any) {
	fmt.Print(a...)
}
