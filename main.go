package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	localTokenUrl = "http://192.168.199.1/local-ssh/api?method=get"
	routerInfoUrl = "http://192.168.199.1/cgi-bin/turbo/proxy/router_info"
	launchSshUrl  = "http://192.168.199.1/local-ssh/api?method=valid&data=%s"
)

type LocalTokenResp struct {
	Data string
}

type LaunchSshResp struct {
	Data string
}

type RouterInfoResp struct {
	Data RouterInfoData
}

type RouterInfoData struct {
	Uuid string
}

func main() {
	sshLauncher()
	fmt.Print("按回车退出...")
	var input string
	_, _ = fmt.Scanln(&input)
}

func sshLauncher() {
	ltr := LocalTokenResp{}
	rir := RouterInfoResp{}
	osr := LaunchSshResp{}
	var err error

	for i := 0; i < 5; i++ {
		if i != 0 {
			fmt.Printf("第%d次重试\n\n", i)
		}

		fmt.Println("开始获取local_token")
		err = httpGet(localTokenUrl, &ltr)
		if err != nil {
			fmt.Printf("获取local_token出错: \n%v\n\n", err)
			continue
		}
		fmt.Printf("获取local_token成功:\n%s\n\n", ltr.Data)

		fmt.Println("开始获取uuid")
		err = httpGet(routerInfoUrl, &rir)
		if err != nil {
			fmt.Printf("获取uuid出错: \n%v\n\n", err)
			continue
		}
		fmt.Printf("获取uuid成功:\n%s\n\n", rir.Data.Uuid)

		fmt.Println("开始计算cloud_token")

		cloudToken := ""
		cloudToken, err = getCloudToken(rir.Data.Uuid, ltr.Data)
		if err != nil {
			fmt.Printf("获取cloud_token出错: \n%v\n\n", err)
			continue
		}
		fmt.Printf("获取local_token成功:\n%s\n\n", cloudToken)

		err = httpGet(fmt.Sprintf(launchSshUrl, cloudToken), &osr)
		if err != nil {
			fmt.Printf("开启ssh端口出错: %v\n\n", err)
			continue
		}
		if strings.Contains(osr.Data, "ssh port is") {
			suc := strings.ReplaceAll(osr.Data, "Success: ssh port is ", "ssh开启成功, 端口号为:")
			fmt.Println(suc)
		} else {
			fmt.Println(ltr.Data)
			fmt.Println(rir.Data.Uuid)
			fmt.Println(cloudToken)
		}
		break
	}
}

func getCloudToken(uuid, localToken string) (string, error) {
	key := sha1Sum(uuid)
	msg := tokenToMsg(localToken)
	res := hmacSha1(msg, key)
	fmt.Println("cloud_token: ", res)
	return "", nil
}

func tokenToMsg(cipher string) []byte {
	decodedLocalToken, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		fmt.Println("Err StdEncoding:", err.Error())
	}
	splitToken := strings.Split(string(decodedLocalToken), ",")
	i, err := strconv.Atoi(splitToken[2])
	if err != nil {
		fmt.Println("String->Int: Err", err)
	}
	i += 1
	splitToken[2] = strconv.Itoa(i)
	str := strings.Join(splitToken[:3], ",")
	return []byte(str)
}

func sha1Sum(uuid string) []byte {
	result := sha1.Sum([]byte(uuid))
	return result[:]
}

func hmacSha1(msg, key []byte) string {
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func httpGet(url string, v interface{}) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, v)
	if err != nil {
		return err
	}
	return nil
}
