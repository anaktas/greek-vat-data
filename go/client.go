package main

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

var timeout = time.Duration(30 * time.Second)

const (
	Endpoint string = "https://www1.gsis.gr:443/webtax2/wsgsis/RgWsPublic/RgWsPublicPort"
	Action   string = "http://gr/gsis/rgwspublic/RgWsPublic.wsdl/rgWsPublicAfmMethod"
	XmlsEnv  string = "http://schemas.xmlsoap.org/soap/envelope/"

	XmlsNS  string = "http://gr/gsis/rgwspublic/RgWsPublic.wsdl"
	XmlsXsi string = "http://www.w3.org/2001/XMLSchema-instance"
	XmlsXsd string = "http://www.w3.org/2001/XMLSchema"
	XmlsNs1 string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
)

type Client struct {
	Endpoint string
	Action   string
}

type SOAPEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Header  *SOAPHeader
	Body    *SOAPBody
}

type SOAPHeader struct {
	XMLName xml.Name      `xml:"http://schemas.xmlsoap.org/soap/envelope/ Header"`
	Items   []interface{} `xml:",omitempty"`
}

type SOAPBody struct {
	XMLName xml.Name    `xml:"http://schemas.xmlsoap.org/soap/envelop/ Body"`
	Fault   *SOAPFault  `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

type SOAPFault struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelop/ Fault"`
	Code    string   `xml:"faultcode,omitempty"`
	String  string   `xml:"faultstring,omitempty"`
	Actor   string   `xml:"faultactor,omitempty"`
	Detail  string   `xml:"detail,omitempty"`
}

func (b *SOAPBody) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}

	var (
		token    xml.Token
		err      error
		consumed bool
	)
Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}

		if token == nil {
			break
		}

		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError("Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Space == "http://schemas.xmlsoap.org/soap/envelope/" && se.Name.Local == "Fault" {
				b.Fault = &SOAPFault{}
				b.Content = nil

				err = d.DecodeElement(b.Fault, &se)
				if err != nil {
					return err
				}

				consumed = true
			} else {
				if err = d.DecodeElement(b.Content, &se); err != nil {
					return err
				}

				consumed = true
			}
		case xml.EndElement:
			break Loop
		}
	}

	return nil
}

type RequestEnvelope struct {
	XMLName xml.Name       `xml:"env:Envelope"`
	Env     string         `xml:"xmlns:env,attr"`
	NS      string         `xml:"xmlns:ns,attr"`
	XSI     string         `xml:"xmlns:xsi,attr"`
	XSD     string         `xml:"xmlns:xsd,attr"`
	NS1     string         `xml:"xmlns:ns1,attr"`
	Header  *RequestHeader `xml:",omitempty"`
	Body    *RequestBody   `xml:",omitempty"`
}

type RequestBody struct {
	XMLName xml.Name           `xml:"env:Body"`
	Method  *RequestMethodBody `xml:",omitempty"`
	Version *VersionInfo       `xml:",omitempty"`
}

type RequestHeader struct {
	XMLName xml.Name        `xml:"env:Header"`
	Header  *SecurityHeader `xml:",omitempty"`
}

type SecurityHeader struct {
	XMLName xml.Name       `xml:"ns1:Security"`
	Token   *UsernameToken `xml:",omitempty"`
}

type RequestMethodBody struct {
	XMLName     xml.Name      `xml:"ns:rgWsPublicAfmMethod"`
	Input       *InputRec     `xml:",omitempty"`
	Output      *OutputRec    `xml:",omitempty"`
	Firm        *FirmRec      `xml:",omitempty"`
	SeqId       *OutCallSeqId `xml:",omitempty"`
	OutErrorRec *OutErrorRec  `xml:",omitempty"`
}

type VersionInfo struct {
	XMLName xml.Name `xml:"ns:rgWsPublicVersionInfo"`
}

type UsernameToken struct {
	XMLName  xml.Name  `xml:"ns1:UsernameToken"`
	Username *Username `xml:",omitempty"`
	Password *Password `xml:",omitempty"`
}

type InputRec struct {
	XMLName       xml.Name       `xml:"RgWsPublicInputRt_in"`
	Type          string         `xml:"xsi:type,attr"`
	AfmCalledBy   *AfmCalledBy   `xml:",omitempty"`
	AfmCalledFrom *AfmCalledFrom `xml:",omitempty"`
}

type OutputRec struct {
	XMLName xml.Name `xml:"RgWsPublicBasicRt_out"`
	Type    string   `xml:"xsi:type,attr"`
}

type FirmRec struct {
	XMLName xml.Name `xml:"arrayOfRgWsPublicFirmActRt_out"`
	Type    string   `xml:"xsi:type,attr"`
}

type OutCallSeqId struct {
	XMLName xml.Name `xml:"pCallSeqId_out"`
	Type    string   `xml:"xsi:type,attr"`
	SeqId   int      `xml:",omitempty"`
}

type OutErrorRec struct {
	XMLName xml.Name `xml:"pErrorRec_out"`
	Type    string   `xml:"xsi:type,attr"`
}

type Username struct {
	XMLName xml.Name `xml:"ns1:Username"`
	Data    string   `xml:",chardata"`
}

type Password struct {
	XMLName xml.Name `xml:"ns1:Password"`
	Data    string   `xml:",chardata"`
}

type AfmCalledBy struct {
	XMLName xml.Name `xml:"ns:afm_called_by"`
	Data    string   `xml:",chardata"`
}

type AfmCalledFrom struct {
	XMLName xml.Name `xml:"ns:afm_called_for"`
	Data    string   `xml:",chardata"`
}

func NewClient() *Client {
	return &Client{
		Endpoint: Endpoint,
		Action:   Action,
	}
}

func (c *Client) GetVAT(username, password, afmBy, afmFor string) error {
	envelope := c.CreateRequest(username, password, afmBy, afmFor)

	res, err := c.performRequest(envelope)
	if err != nil {
		return err
	}

	log.Println(string(res))
	// respEnvelope := new(SOAPEnvelope)
	// respEnvelope.Body = SOAPBody{Content: response}
	// err = xml.Unmarshal(rawbody, respEnvelope)
	// if err != nil {
	// 	return err
	// }
	// fault := respEnvelope.Body.Fault
	// if fault != nil {
	// 	return fault
	// }

	return nil
}

func (c *Client) GetVersion() error {
	envelope := c.CreateVersionRequest()

	res, err := c.performRequest(envelope)
	if err != nil {
		return err
	}

	log.Println(string(res))
	// respEnvelope := new(SOAPEnvelope)
	// respEnvelope.Body = SOAPBody{Content: response}
	// err = xml.Unmarshal(rawbody, respEnvelope)
	// if err != nil {
	// 	return err
	// }
	// fault := respEnvelope.Body.Fault
	// if fault != nil {
	// 	return fault
	// }

	return nil
}

func (c *Client) CreateSecurityHeader(username string, password string) *RequestHeader {
	header := &RequestHeader{}
	securityHeader := &SecurityHeader{}

	token := &UsernameToken{
		Username: &Username{Data: username},
		Password: &Password{Data: password},
	}

	securityHeader.Token = token

	header.Header = securityHeader

	return header
}

func (c *Client) CreateRequestBody(afmBy string, afmFor string) *RequestBody {
	body := &RequestBody{}
	method := &RequestMethodBody{}

	input := &InputRec{
		Type:          "ns:RgWsPublicInputRtUser",
		AfmCalledBy:   &AfmCalledBy{Data: afmBy},
		AfmCalledFrom: &AfmCalledFrom{Data: afmFor},
	}

	outpout := &OutputRec{
		Type: "ns:RgWsPublicBasicRtUser",
	}

	firm := &FirmRec{
		Type: "ns:RgWsPublicFirmActRtUserArray",
	}

	seqId := &OutCallSeqId{
		Type:  "xsd:decimal",
		SeqId: 0,
	}

	outError := &OutErrorRec{
		Type: "ns:GenWsErrorRtUser",
	}

	method.Input = input
	method.Output = outpout
	method.Firm = firm
	method.SeqId = seqId
	method.OutErrorRec = outError

	body.Method = method

	return body
}

func (c *Client) CreateRequest(username, password, afmBy, afmFor string) RequestEnvelope {
	requestEnvelope := RequestEnvelope{}

	requestEnvelope.Env = XmlsEnv
	requestEnvelope.NS = XmlsNS
	requestEnvelope.XSI = XmlsXsi
	requestEnvelope.XSD = XmlsXsd
	requestEnvelope.NS1 = XmlsNs1

	requestEnvelope.Header = c.CreateSecurityHeader(username, password)
	requestEnvelope.Body = c.CreateRequestBody(afmBy, afmFor)

	return requestEnvelope
}

func (c *Client) CreateVersionRequest() RequestEnvelope {
	requestEnvelope := RequestEnvelope{}

	requestEnvelope.Env = XmlsEnv
	requestEnvelope.NS = XmlsNS
	requestEnvelope.XSI = XmlsXsi
	requestEnvelope.XSD = XmlsXsd
	requestEnvelope.NS1 = XmlsNs1

	requestEnvelope.Header = &RequestHeader{}
	requestEnvelope.Body = &RequestBody{
		Version: &VersionInfo{},
	}

	return requestEnvelope
}

func dialTimeout(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

func (c *Client) performRequest(v interface{}) ([]byte, error) {
	buffer := new(bytes.Buffer)
	encoder := xml.NewEncoder(buffer)

	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	if err := encoder.Flush(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.Endpoint, buffer)
	if err != nil {
		return nil, err
	}

	headers := http.Header{
		"Content-Type": []string{"application/soap+xml; charset=\"UTF-8\""},
		"SOAPAction":   []string{c.Action},
		"User-Agent":   []string{"goclient"},
	}

	req.Header = headers

	req.Close = true

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		Dial: dialTimeout,
	}

	client := &http.Client{Transport: tr}

	dump, err := httputil.DumpRequest(req, true)
	if err != nil {
		log.Println(err)
	}

	log.Println(string(dump))

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	rawbody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return rawbody, nil
}
