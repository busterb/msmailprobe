
package main

import(
	"net/http"
	"net"
	"log"
	"fmt"
	"io/ioutil"
	"time"
	"strings"
	b64 "encoding/base64"
	"flag"
	"os"
	"crypto/tls"
	"sort"
	"sync"
)

const (
	BrightGreen     = "\033[1;32m%s\033[0m"
	BrightYellow    = "\033[1;33m%s\033[0m"
	BrightRed       = "\033[1;31m%s\033[0m"
	WhiteUnderline  = "\033[1;4m%s\033[0m"
	ClearColor      = "\033[1;1m%s\033[0m"
)

func main() {
	userenumCommand := flag.NewFlagSet("userenum", flag.ExitOnError)
	onpremFlag := userenumCommand.Bool("onprem", false, "Flag to specify an On-Premise instance of Exchange")
	o365Flag := userenumCommand.Bool("o365", false, "Use this flag if Exchange services are hosted by Office 365.")
	hostFlag := userenumCommand.String("t","","Host pointing to Exchange services.")
//	domainFlag := userenumCommand.String("d","","Internal domain for targeted host.")
	userlistFlag := userenumCommand.String("U","","Userlist file import flag")
	usernameFlag := userenumCommand.String("u","","Single username value.")
	emaillistFlag := userenumCommand.String("E", "", "Email list file path flag (o365)")
	emailFlag := userenumCommand.String("e","","Single email address to enumerate (o365)")
	outfileFlag := userenumCommand.String("o", "", "Flag used for outputting valid users/emails.")
	threadFlag := userenumCommand.Int("threads", 5, "Flag used for setting amount of threads for requests being made.")

	identifyCommand := flag.NewFlagSet("identify", flag.ExitOnError)
	identifyHost := identifyCommand.String("t", "","Host for targeted Exchange services.")

	examplesCommand := flag.NewFlagSet("examples", flag.ExitOnError)


	if len(os.Args) <= 1 {
		fmt.Println("~~MSMailProbe v1.001~~")
		fmt.Println("Supply either the identify, userenum, or examples command for further assistance.\n")
		fmt.Println("View examples:")
		fmt.Println("	./msmailprobe examples")
		fmt.Println("	./msmailprobe identify")
		fmt.Println("	./msmailprobe userenum")
		return
	}

	switch os.Args[1] {
		case "userenum":
			userenumCommand.Parse(os.Args[2:])
		case "identify":
			identifyCommand.Parse(os.Args[2:])
		case "examples":
			examplesCommand.Parse(os.Args[2:])
		default:
			fmt.Printf("%q is not valid command.\n",os.Args[1])
			os.Exit(2)
	}
	if userenumCommand.Parsed() {
		if *onpremFlag == false && *o365Flag == false {
			fmt.Println("Please specify --onprem or --o365 when using the userenum command.")
			fmt.Println("  *add one of the two flags above for more specific help")
			return
		}
		if *threadFlag > 100 {
			fmt.Println("[i] Exceeded maximum recommended number of threads, setting to 5.")
			*threadFlag = 5
		}
		if *onpremFlag == true && *o365Flag == false {
			if *userlistFlag != "" && *hostFlag != "" {
				if *outfileFlag == "" {
					avgResponse := basicAuthAvgTime(*hostFlag)
					determineValidUsers(*hostFlag, avgResponse,importUserList(*userlistFlag), *threadFlag)
				}
				if *outfileFlag != "" {
					avgResponse := basicAuthAvgTime(*hostFlag)
					writeFile(*outfileFlag, determineValidUsers(*hostFlag, avgResponse,importUserList(*userlistFlag), *threadFlag))
				}
			} else if  *usernameFlag != "" && *hostFlag != "" {
				avgResponse := basicAuthAvgTime(*hostFlag)
				determineValidUsers(*hostFlag, avgResponse,[]string{*usernameFlag}, *threadFlag)
			} else {
				fmt.Println("~~On-Premise Exchange User Enumeration~~\n")
				fmt.Println("Flags to use:")
				fmt.Println("	-t to specify target host")
				fmt.Println("	-U for user list OR -u for single username")
				fmt.Println("	-o [optional]to specify an out file for valid users identified")
				fmt.Println("	--threads [optional] for setting amount of requests to be made concurrently\n")
				fmt.Println("Examples:")
				fmt.Println("	./msmailprobe userenum --onprem -t mail.target.com -U userList.txt -o validusers.txt --threads 25")
				fmt.Println("	./msmailprobe userenum --onprem -t mail.target.com -u admin")
			}
		}
		if *onpremFlag == false && *o365Flag == true {
			if *emaillistFlag == "" && *emailFlag=="" && *outfileFlag=="" {
				fmt.Println("~~Office 365 User Enumeration~~\n")
				fmt.Println("Flags to use:")
				fmt.Println("	-E for email list OR -e for single email address")
				fmt.Println("	-o [optional]to specify an out file for valid emails identified")
				fmt.Println("	--threads [optional] for setting amount of requests to be made concurrently\n")
				fmt.Println("Examples:")
				fmt.Println("	./msmailprobe userenum --o365 -E emailList.txt -o validemails.txt --threads 25")
				fmt.Println("	./msmailprobe userenum --o365 -e admin@target.com")
				return
			}
			if *outfileFlag == "" {
				if *emaillistFlag != "" && *emailFlag == "" {
					o365enum(importUserList(*emaillistFlag), *threadFlag)
				} else if *emailFlag != "" && *emaillistFlag == "" {
					o365enum([]string{*emailFlag}, *threadFlag)
				}
			} else if *outfileFlag != "" {
				if *emailFlag != "" && *emaillistFlag == "" {
					writeFile(*outfileFlag, o365enum([]string{*emailFlag}, *threadFlag))
				} else if *emailFlag == "" && *emaillistFlag != "" {
					writeFile(*outfileFlag, o365enum(importUserList(*emaillistFlag), *threadFlag))
				} else {
					fmt.Println("For help:")
					fmt.Println("./msmailprobe userenum --o365")
				}
			} else {
				fmt.Println("error2")
			}
		}
		if *onpremFlag == true && *o365Flag == true {
			fmt.Println("Please only use one of the --o365 or --onprem flags.")
			return
		}
	}

	if identifyCommand.Parsed() {
		if *identifyHost != "" {
			harvestInternalDomain(*identifyHost, true)
			urlEnum(*identifyHost)
		} else {
			fmt.Println("~~Identify Command~~\n")
			fmt.Println("Flag to use:")
				fmt.Println("	-t to specify target host\n")
				fmt.Println("Example:")
				fmt.Println("	./msmailprobe identify -t mail.target.com\n")
		}
	}

	if examplesCommand.Parsed() {
		fmt.Println("./msmailprobe identify -h mail.target.com")
		fmt.Println("./msmailprobe userenum --onprem -t mail.target.com -U users.txt -o validusers.txt --threads 20")
		fmt.Println("./msmailprobe userenum --onprem -t mail.target.com -u admin")
		fmt.Println("./msmailprobe userenum --o365 -E emailList.txt -o validemails.txt --threads 50")
		fmt.Println("./msmailprobe userenum --o365 -e admin@target.com")
	}
}

func harvestInternalDomain(host string, outputDomain bool) string {
	if outputDomain == true {
		fmt.Println("\nAttempting to harvest internal domain:")
	}
	url1 := "https://"+host+"/ews"
	url2 := "https://"+host+"/autodiscover/autodiscover.xml"
	url3 := "https://"+host+"/rpc"
	url4 := "https://"+host+"/mapi"
	url5 := "https://"+host+"/oab"
	url6 := "https://autodiscover."+host+"/autodiscover/autodiscover.xml"
	var urlToHarvest string
	if webRequestCodeResponse(url1) == 401 {
		urlToHarvest = url1
	} else if webRequestCodeResponse(url2) == 401 {
		urlToHarvest = url2
	} else if webRequestCodeResponse(url3) == 401 {
		urlToHarvest = url3
	} else if webRequestCodeResponse(url4) == 401 {
		urlToHarvest = url4
	} else if webRequestCodeResponse(url5) == 401 {
		urlToHarvest = url5
	} else if webRequestCodeResponse(url6) == 401 {
		urlToHarvest = url6
	} else {
		fmt.Printf(BrightYellow,"[-] ")
		fmt.Print("Unable to resolve host provided to harvest internal domain name.\n")
	}

	tr := &http.Transport {
	        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	timeout := time.Duration(3 * time.Second)

	client := &http.Client {
	        Timeout: timeout,
		Transport: tr,

	}
	req, err := http.NewRequest("GET", urlToHarvest, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36")
	req.Header.Set("Authorization", "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")
	resp, err := client.Do(req)


	if err != nil {
		return ""
	}
	ntlmResponse := resp.Header.Get("WWW-Authenticate")
	data := strings.Split(ntlmResponse, " ")
	base64DecodedResp, err := b64.StdEncoding.DecodeString(data[1])
	if err != nil {
		fmt.Println("Unable to parse NTLM response for internal domain name")
	}

	var continueAppending bool
	var internalDomainDecimal []byte
	for _, decimalValue := range base64DecodedResp {
		if decimalValue == 0 {
			continue
		}
		if decimalValue == 2 {
			continueAppending = false
		}
		if continueAppending == true {
			internalDomainDecimal = append(internalDomainDecimal, decimalValue)
		}
		if decimalValue == 15 {
			continueAppending = true
			continue
		}
	}
	if outputDomain == true {
		fmt.Printf(BrightGreen, "[+] ")
		fmt.Print("Internal Domain: ")
		fmt.Printf(BrightGreen, string(internalDomainDecimal)+ "\n")
	}
	return string(internalDomainDecimal)
}

func importUserList(tempname string) []string {
    userFileBytes, err := ioutil.ReadFile(tempname)
    if err != nil {
        fmt.Print(err)
    }
    var userFileString = string(userFileBytes)
    userArray := strings.Split(userFileString, "\n")
    //Delete last unnecessary newline inserted into this slice
    userArray = userArray[:len(userArray)-1]
    return userArray
}

func determineValidUsers(host string, avgResponse time.Duration, userlist []string, threads int) []string {
	limit := threads
	var wg sync.WaitGroup
	mux := &sync.Mutex{}
	queue := make(chan string)

	/*Keep in mind you, nothing has been added to handle successful auths
	  so the password for auth attempts has been hardcoded to something
	  that is not likely to be correct.
	 */
	pass := "Summer2018978"
	internaldomain := harvestInternalDomain(host, false)
	url1 := "https://"+host+"/autodiscover/autodiscover.xml"
	url2 := "https://"+host+"/Microsoft-Server-ActiveSync"
	url3 := "https://autodiscover."+host+"/autodiscover/autodiscover.xml"
	var urlToHarvest string
	if webRequestCodeResponse(url1) == 401 {
		urlToHarvest = url1
	} else if webRequestCodeResponse(url2) == 401 {
		urlToHarvest = url2
	} else if webRequestCodeResponse(url3) == 401 {
		urlToHarvest = url3
	} else {
		fmt.Println("[-] Unable to resolve host provided to determine valid users.")
		os.Exit(2)
	}
	var validusers []string
	tr := &http.Transport {
	        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for user := range queue {
				startTime := time.Now()
				webRequestBasicAuth(urlToHarvest, internaldomain + "\\" + user, pass, tr)
				elapsedTime := time.Since(startTime)

				if float64(elapsedTime) < float64(avgResponse)*0.77 {
					mux.Lock()
					fmt.Printf(BrightGreen, "[+] " +user + " - ")
					fmt.Printf(BrightGreen,elapsedTime)
					fmt.Println("")
					validusers = append(validusers, user)
					mux.Unlock()
				} else {
					mux.Lock()
					fmt.Print("[-] " + user + " - ")
					fmt.Println(elapsedTime)
					mux.Unlock()
				}
			}
		}(i)
	}

	for i:=0; i < len(userlist); i++ {
		queue <- userlist[i]
	}


	close(queue)
	wg.Wait()
	return validusers
}

func basicAuthAvgTime(host string) time.Duration {
	internaldomain := harvestInternalDomain(host, false)
	url1 := "https://"+host+"/autodiscover/autodiscover.xml"
	url2 := "https://"+host+"/Microsoft-Server-ActiveSync"
	url3 := "https://autodiscover."+host+"/autodiscover/autodiscover.xml"
	var urlToHarvest string
	if webRequestCodeResponse(url1) == 401 {
		urlToHarvest = url1
	} else if webRequestCodeResponse(url2) == 401 {
		//fmt.Println("[i] ActiveSync not resolved.. failing over to AutoDiscover")
		urlToHarvest = url2
	} else if webRequestCodeResponse(url3) == 401 {
		//fmt.Println("[i] ActiveSync not resolved.. failing over to AutoDiscover")
		urlToHarvest = url3
	} else {
		println("[-] Unable to resolve host provided to determine valid users.")
		os.Exit(2)
	}

	//We are determining sample auth response time for invalid users, the password used is irrelevant.
	pass := "Summer201823904"
	tr := &http.Transport {
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	fmt.Println("\nCollecting sample auth times...")

	var sliceOfTimes []float64
	var medianTime float64

	usernamelist := []string{"sdfsdskljdfhkljhf","ssdlfkjhgkjhdfsdfw","sdfsdfdsfff","sefsefsefsss","lkjhlkjhiuyoiuy","khiuoiuhohuio","s2222dfs45g45gdf","sdfseddf3333"}
	for i := 0; i < len(usernamelist)-1; i++ {
		startTime := time.Now()
		webRequestBasicAuth(urlToHarvest,internaldomain + "\\" + usernamelist[i], pass, tr)
		//req.SetBasicAuth(internaldomain + "\\" + usernamelist[i], pass)
		elapsedTime := time.Since(startTime)
		if elapsedTime > time.Second * 15 {
			fmt.Println("\nResponse taking longer than 15 seconds, setting time:")
			fmt.Println("[i] Avg Response:", time.Duration(elapsedTime), "\n")
			return time.Duration(elapsedTime)
		}
		if i != 0 {
			fmt.Println(elapsedTime)
			sliceOfTimes = append(sliceOfTimes, float64(elapsedTime))
		}
	}
	sort.Float64s(sliceOfTimes)
	if len(sliceOfTimes)%2 == 0 {
		positionOne := len(sliceOfTimes)/2 -1
		positionTwo := len(sliceOfTimes)/2
		medianTime = (sliceOfTimes[positionTwo] +sliceOfTimes[positionOne])/2
	} else if len(sliceOfTimes)%2 != 0 {
		position := len(sliceOfTimes)/2 -1
		medianTime = sliceOfTimes[position]
	} else {
		fmt.Println("Error determining whether length of times gathered is even or odd to obtain median value.")
	}
	fmt.Println("[i] Avg Response:", time.Duration(medianTime), "\n")
	return time.Duration(medianTime)
}

func o365enum(emaillist []string, threads int) []string {
	limit := threads
	var wg sync.WaitGroup
	mux := &sync.Mutex{}
	queue := make(chan string)
	//limit := 100

	/*Keep in mind you, nothing has been added to handle successful auths
	  so the password for auth attempts has been hardcoded to something
	  that is not likely to be correct.
	 */
	pass := "Summer2018876"
	URI := "https://outlook.office365.com/Microsoft-Server-ActiveSync"
	var validemails []string

	tr := &http.Transport {
	        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for email := range queue {
				responseCode := webRequestBasicAuth(URI, email, pass , tr)
				if strings.Contains(email, "@") && responseCode == 401 {
					mux.Lock()
					fmt.Printf(BrightGreen,"[+]  "+ email + " - 401 \n")
					validemails = append(validemails, email)
					mux.Unlock()
				}else if strings.Contains(email, "@") && responseCode == 404 {
					mux.Lock()
					fmt.Printf("[-]  %s - %d \n", email,responseCode)
					mux.Unlock()
				}else {
					mux.Lock()
					fmt.Printf("[i] Unusual Response: %s - %d \n", email, responseCode)
					mux.Unlock()
				}
			}
		}(i)
	}

	for i:=0; i < len(emaillist); i++ {
		queue <- emaillist[i]
	}

	close(queue)
	wg.Wait()
	return validemails
}

func webRequestBasicAuth(URI string, user string, pass string, tr *http.Transport) int {
	timeout := time.Duration(45 * time.Second)
	client := &http.Client {
		Timeout: timeout,
		Transport: tr,
	}
	req, err := http.NewRequest("GET", URI, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 11_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1")
	req.SetBasicAuth(user, pass)
	resp, errr := client.Do(req)
	if errr != nil {
		fmt.Printf("[i] Potential Timeout - %s \n", user)
		fmt.Printf("[i] One of your requests has taken longer than 45 seconds to respond.")
		fmt.Printf("[i] Consider lowering amount of threads used for enumeration.")
		log.Fatal(err)
	}
	return resp.StatusCode
}

func urlEnum(hostInput string) {
	//var logger = log.New(os.Stdout, "", 0)
	//Beginning of o365 enumeration
	//target-com.mail.protection.outlook.com
	hostSlice := strings.Split(hostInput, ".")
	//rootDomain := hostSlice[len(hostSlice)-2] + "." + hostSlice[len(hostSlice)-1]
	o365Domain := hostSlice[len(hostSlice)-2] + "-" + hostSlice[len(hostSlice)-1] + ".mail.protection.outlook.com"
	addr,err := net.LookupIP(o365Domain)
	if err != nil {
		fmt.Printf(BrightYellow,"[-] ")
		fmt.Println("Domain is not using o365 resources.")
	} else if addr == nil {
		fmt.Println("error")
	} else {
		fmt.Printf(BrightGreen,"[+] ")
		fmt.Println("Domain is using o365 resources.")
	}
	asURI := "https://" + hostInput + "/Microsoft-Server-ActiveSync"
	adURI := "https://" + hostInput + "/autodiscover/autodiscover.xml"
	ad2URI := "https://autodiscover." + hostInput + "/autodiscover/autodiscover.xml"
	owaURI := "https://" + hostInput + "/owa"
	timeEndpointsIdentified := false
	fmt.Println("")
	fmt.Println("\nIdentifying endpoints vulnerable to time-based enumeration:")
	timeEndpoints := []string{asURI,adURI,ad2URI,owaURI}
	for _, uri := range timeEndpoints {
		responseCode := webRequestCodeResponse(uri)
		if responseCode == 401 {
			fmt.Printf(BrightGreen,"[+] ")
			fmt.Println(uri)
			timeEndpointsIdentified = true
		}
		if responseCode == 200 {
			fmt.Printf(BrightGreen,"[+] ")
			fmt.Println(uri)
			timeEndpointsIdentified = true
		}
	}
	if timeEndpointsIdentified == false {
		fmt.Printf(BrightYellow, "[-] ")
		fmt.Println("No Exchange endpoints vulnerable to time-based enumeration discovered.")
	}
	fmt.Println("\n\nIdentifying exposed Exchange endpoints for potential spraying:")
	passEndpointIdentified := false
	rpcURI := "https://" + hostInput + "/rpc"
	oabURI := "https://" + hostInput + "/oab"
	ewsURI := "https://" + hostInput + "/ews"
	mapiURI := "https://" + hostInput + "/mapi"

	passEndpoints401 := []string{oabURI, ewsURI, mapiURI, asURI, adURI,ad2URI,rpcURI}
	for _, uri := range passEndpoints401 {
		responseCode := webRequestCodeResponse(uri)
		if responseCode == 401 {
			fmt.Printf(BrightGreen,"[+] ")
			fmt.Println(uri)
			passEndpointIdentified = true
		}
	}
	ecpURI := "https://" + hostInput + "/ecp"
	endpoints200 := []string{ecpURI, owaURI}
	for _, uri := range endpoints200 {
		responseCode := webRequestCodeResponse(uri)
		if responseCode == 200 {
			fmt.Printf(BrightGreen,"[+] ")
			fmt.Println(uri)
			passEndpointIdentified = true
		}
	}
	if passEndpointIdentified == false {
		fmt.Printf(BrightYellow, "[-] ")
		fmt.Println("No onprem Exchange services identified.")
	}
}

func webRequestCodeResponse(URI string) int {
	tr := &http.Transport {
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	timeout := time.Duration(3 * time.Second)
	client := &http.Client {
		Timeout: timeout,
		Transport: tr,
	}
	req, err := http.NewRequest("GET", URI, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 11_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1")
	resp, err := client.Do(req)
	if err != nil {
		return 0
		//log.Fatal(err)
	}
	return resp.StatusCode
}

func writeFile(filename string, values []string) {
	if len(values) == 0 {
		return
	}
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	for _, value := range values {
		fmt.Fprintln(f, value)
	}
}
