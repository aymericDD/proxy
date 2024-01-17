// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package httpfault

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/cilium/proxy/proxylib/proxylib"
)

// HTTP Fault Parser
type httpFaultRule struct {
	method             string
	statusCode         int
	probability        float64
	probabilitySource  *rand.Rand
	delayRequest       time.Duration
	delayResponse      time.Duration
	rewriteStatus      string
	rewriteBody        string
	addRequestHeaders  map[string]string
	addResponseHeaders map[string]string
	pathRegexp         *regexp.Regexp
}

func (r *httpFaultRule) matchRequest(req *http.Request) bool {
	logrus.Debugf("Matches() called on HTTP request, rule: %#v", r)

	if r.probability != float64(0) {
		if r.probabilitySource.Float64() > r.probability {
			return false
		}
	}

	if r.method != "" && r.method != req.Method {
		return false
	}

	if r.pathRegexp != nil && req.URL != nil {
		if !r.pathRegexp.MatchString(req.URL.EscapedPath()) {
			return false
		}
	}

	for k, v := range r.addRequestHeaders {
		req.Header.Add(k, v)
	}

	if r.delayRequest != time.Duration(0) {
		logrus.Debugf("Delaying request for %v", r.delayRequest)
		time.Sleep(r.delayRequest)
		req.Header.Add("X-Cilium-Delay", fmt.Sprintf("Delayed request by %s", r.delayRequest))
	}

	return true
}

func (r *httpFaultRule) matchResponse(resp *http.Response) bool {
	logrus.Debugf("Matches() called on HTTP response, rule: %#v", r)

	if r.probability != float64(0) {
		if r.probabilitySource.Float64() > r.probability {
			return false
		}
	}

	if r.statusCode != 0 && r.statusCode != resp.StatusCode {
		return false
	}

	if r.delayResponse != time.Duration(0) {
		logrus.Debugf("Delaying response for %v", r.delayRequest)
		time.Sleep(r.delayResponse)
		resp.Header.Add("X-Cilium-Delay", fmt.Sprintf("Delayed response by %s", r.delayRequest))
	}

	for k, v := range r.addResponseHeaders {
		resp.Header.Add(k, v)
	}

	if r.rewriteStatus != "" {
		resp.Status = r.rewriteStatus
		chunks := strings.SplitN(r.rewriteStatus, " ", 2)
		if len(chunks) == 2 {
			i, err := strconv.ParseInt(chunks[0], 10, 64)
			if err == nil {
				resp.StatusCode = int(i)
			}
		}
		resp.Header.Add("X-Cilium-Modified-Status-Code", "The status code has been modified by Cilium")
	}

	if r.rewriteBody != "" {
		resp.ContentLength = int64(len(r.rewriteBody))
		resp.Body = io.NopCloser(strings.NewReader(r.rewriteBody))
		resp.Header.Add("X-Cilium-Modified-Body", "The body has been modified by Cilium")
	}

	return true
}

func (r *httpFaultRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'
	switch data.(type) {
	case *http.Request:
		req := data.(*http.Request)
		return r.matchRequest(req)

	case *http.Response:
		resp := data.(*http.Response)
		return r.matchResponse(resp)

	default:
		logrus.Warningf("Invalid data passed into Matches(): %#v", data)
		return false
	}
}

type factory struct{}

// Create is called by Envoy when a new connection has been created and a parser must be instantiated
func (f *factory) Create(connection *proxylib.Connection) interface{} {
	logrus.Debugf("ChaosTestingParser Create: %v", connection)

	return &ChaosTestingParser{
		connection: connection,
		reqReader:  newDirectionalReader("request", false),
		respReader: newDirectionalReader("response", true),
	}
}

func init() {
	logrus.Debug("init(): Registering httpFaultParserFactory")
	proxylib.RegisterParserFactory("httpfault", &factory{})
	proxylib.RegisterL7RuleParser("httpfault", ruleParser)
}

type directionalReader struct {
	name             string
	envoyReader      *envoyDataReader
	bufferedReader   *bufio.Reader
	injectionStarted bool
	injectBuffer     []byte
	reply            bool

	bytesReady int
}

func newDirectionalReader(name string, reply bool) *directionalReader {
	p := &directionalReader{
		name:  name,
		reply: reply,
	}
	p.envoyReader = newEnvoyDataReader(name, p)
	p.bufferedReader = bufio.NewReader(p.envoyReader)
	return p
}

func (r *directionalReader) inject(connection *proxylib.Connection, reply bool) int {
	logrus.Debugf("Attempting to inject %d bytes", len(r.injectBuffer))
	n := connection.Inject(reply, r.injectBuffer)
	logrus.Debugf("%s: Injected %d bytes, %d remaining", r.name, n, len(r.injectBuffer)-n)
	if n > 0 && len(r.injectBuffer) != n {
		r.injectBuffer = r.injectBuffer[n:]
		logrus.Debugf("Setting inject buffer to new length %d", len(r.injectBuffer))
	} else {
		logrus.Debugf("Resetting inject buffer")
		r.injectBuffer = nil
	}
	return n
}

func (r *directionalReader) injectLeftovers(connection *proxylib.Connection, reply bool) int {
	if len(r.injectBuffer) > 0 {
		injected := r.inject(connection, reply)
		if injected > 0 {
			return injected
		}
	}

	if r.injectBuffer != nil {
		logrus.Debugf("Resetting inject buffer 2x")
		r.injectBuffer = nil
	}

	return 0
}

type envoyDataReader struct {
	name string
	pipe *directionalReader
	data [][]byte
	skip int
	eof  bool
}

func newEnvoyDataReader(name string, pipe *directionalReader) *envoyDataReader {
	e := &envoyDataReader{
		name: name,
		pipe: pipe,
	}

	return e
}

func (e *envoyDataReader) Read(p []byte) (int, error) {
	logrus.Debugf("%s: attempting to read  %d bytes, have %d slides", e.name, len(p), len(e.data))

	skip := e.skip
OUTER:
	for _, slice := range e.data {
		for skip > 0 {
			logrus.Debugf("%d left to skip", skip)
			if e.skip >= len(slice) {
				logrus.Debugf("%s: read - skipping %d bytes", e.name, len(slice))
				skip -= len(slice)
				continue OUTER
			}

			logrus.Debugf("%s: read - skipping %d bytes", e.name, skip)
			slice = slice[skip:]
			skip = 0
		}

		if len(p) < len(slice) {
			slice = slice[:len(p)]
		}

		logrus.Debugf("%s: returning %d bytes", e.name, len(slice))
		e.skip += len(slice)
		e.eof = false
		copy(p, slice)
		logrus.Debugf("Returning %s", string(slice))
		return len(slice), nil
	}

	logrus.Debugf("returning EOF")
	e.eof = true
	return 0, io.EOF
}

// ChaosTestingParser is an Envoy go extension to induce chaos in
// HTTP/REST-based communication between services
type ChaosTestingParser struct {
	connection     *proxylib.Connection
	reqReader      *directionalReader
	respReader     *directionalReader
	lastRequest    *http.Request
	requestMatched bool
}

func (p *ChaosTestingParser) readRequest() (*http.Request, error) {
	p.reqReader.envoyReader.skip = 0

	logrus.Debugf("Starting to read new HTTP request")
	req, err := http.ReadRequest(p.reqReader.bufferedReader)
	if p.reqReader.envoyReader.eof {
		return nil, nil
	}
	if err != nil {
		logrus.Debugf("Got error...: %s", err)
		return nil, err
	}

	b := new(bytes.Buffer)
	io.Copy(b, req.Body)
	req.Body.Close()
	req.Body = ioutil.NopCloser(b)

	if p.reqReader.envoyReader.eof {
		logrus.Debugf("EOF while reading body")
		return nil, nil
	}

	p.connection.Log(cilium.EntryType_Request,
		&cilium.LogEntry_GenericL7{
			GenericL7: &cilium.L7LogEntry{
				Proto: "http",
				Fields: map[string]string{
					"method": req.Method,
					"url":    req.URL.EscapedPath(),
					"length": fmt.Sprintf("%d", req.ContentLength),
				},
			},
		})

	logrus.Debugf("Read HTTP request: %#v", req)
	return req, nil
}

func (p *ChaosTestingParser) readResponse(req *http.Request) (*http.Response, error) {
	p.respReader.envoyReader.skip = 0

	logrus.Debugf("Starting to read new HTTP response")
	resp, err := http.ReadResponse(p.respReader.bufferedReader, req)
	if p.respReader.envoyReader.eof {
		return nil, nil
	}
	if err != nil {
		logrus.Debugf("Error parsing read response: %s", err)
		return nil, err
	}

	b := new(bytes.Buffer)
	io.Copy(b, resp.Body)
	resp.Body.Close()
	resp.Body = ioutil.NopCloser(b)

	if p.respReader.envoyReader.eof {
		logrus.Debugf("EOF while reading body")
		return nil, nil
	}

	p.connection.Log(cilium.EntryType_Response,
		&cilium.LogEntry_GenericL7{
			GenericL7: &cilium.L7LogEntry{
				Proto: "http",
				Fields: map[string]string{
					"status": resp.Status,
					"length": fmt.Sprintf("%d", resp.ContentLength),
				},
			},
		})

	logrus.Debugf("Read HTTP response: %#v", resp)
	return resp, nil
}

func (p *ChaosTestingParser) OnData(reply, endStream bool, dataArray [][]byte) (proxylib.OpType, int) {
	logrus.Debugf("OnData: reply=%t endStream=%t %d slices", reply, endStream, len(dataArray))

	if reply {
		if injected := p.respReader.injectLeftovers(p.connection, true); injected > 0 {
			logrus.Debugf("Returning INJECT")
			return proxylib.INJECT, injected
		}

		p.respReader.envoyReader.data = dataArray

		resp, err := p.readResponse(p.lastRequest)
		if err != nil {
			logrus.Debugf("Returning ERROR")
			return proxylib.ERROR, int(proxylib.ERROR_INVALID_FRAME_LENGTH)
		}
		if resp == nil {
			logrus.Debugf("Returning MORE")
			return proxylib.MORE, 1
		}

		if !p.respReader.injectionStarted {
			p.respReader.injectionStarted = true
			logrus.Debugf("parsed response %#v", resp)

			// No point in executing the rule on the response if
			// the request did not match
			if p.requestMatched {
				p.connection.Matches(resp)
			}

			buf := new(bytes.Buffer)
			resp.Write(buf)

			if !p.requestMatched || equalBuffer(buf, dataArray) {
				logrus.Debugf("Returning PASS")
				p.respReader.injectionStarted = false
				return proxylib.PASS, len(buf.Bytes())
			}

			p.respReader.injectBuffer = buf.Bytes()
			injected := p.respReader.inject(p.connection, true)
			logrus.Debugf("Returning INJECT")
			return proxylib.INJECT, injected
		}

		p.respReader.injectionStarted = false
		return proxylib.NOP, 0
	}

	if injected := p.reqReader.injectLeftovers(p.connection, false); injected > 0 {
		logrus.Debugf("Returning INJECT")
		return proxylib.INJECT, injected
	}

	p.reqReader.envoyReader.data = dataArray

	req, err := p.readRequest()
	if err != nil {
		logrus.Debugf("Returning ERROR")
		return proxylib.ERROR, int(proxylib.ERROR_INVALID_FRAME_LENGTH)
	}
	if req == nil {
		logrus.Debugf("Returning MORE")
		return proxylib.MORE, 1
	}

	if !p.reqReader.injectionStarted {
		p.lastRequest = req
		p.reqReader.injectionStarted = true
		logrus.Debugf("parsed request %#v", req)

		p.requestMatched = p.connection.Matches(req)
		buf := new(bytes.Buffer)
		req.Write(buf)

		if equalBuffer(buf, dataArray) {
			logrus.Debugf("Returning PASS")
			p.reqReader.injectionStarted = false
			return proxylib.PASS, len(buf.Bytes())
		}

		p.reqReader.injectBuffer = buf.Bytes()
		injected := p.reqReader.inject(p.connection, false)
		logrus.Debugf("Returning INJECT")
		return proxylib.INJECT, injected
	}

	p.reqReader.injectionStarted = false
	return proxylib.NOP, 0
}

func equalBuffer(buf *bytes.Buffer, data [][]byte) bool {
	var (
		b      = buf.Bytes()
		offset = 0
	)

	for _, d := range data {
		if len(d)+offset > len(b) {
			return false
		}

		if !bytes.Equal(b[offset:offset+len(d)], d) {
			return false
		}

		offset += len(d)
	}

	return true
}

func parseKeyValueList(val string) (result map[string]string) {
	result = map[string]string{}
	for _, header := range strings.Split(val, ",") {
		kv := strings.SplitN(header, "=", 2)
		if len(kv) == 2 {
			result[kv[0]] = kv[1]
		} else {
			result[kv[0]] = ""
		}
	}
	return
}

// ruleParser parses protobuf L7 rules to enforcement objects
// May panic
func ruleParser(rule *cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
	var rules []proxylib.L7NetworkPolicyRule

	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return rules
	}
	for _, l7Rule := range l7Rules.GetL7AllowRules() {
		var cr httpFaultRule

		for k, v := range l7Rule.Rule {
			switch k {
			case "method":
				cr.method = v

			case "path":
				r, err := regexp.Compile(v)
				if err != nil {
					proxylib.ParseError(fmt.Sprintf("unable to parse regular exprresion for method '%s': %s", v, err), rule)
				} else {
					cr.pathRegexp = r
				}

			case "probability":
				f, err := strconv.ParseFloat(v, 64)
				if err != nil {
					proxylib.ParseError(fmt.Sprintf("unable to parse probability %s: %s", v, err), rule)
				} else {
					cr.probabilitySource = rand.New(rand.NewSource(time.Now().UnixNano()))
					cr.probability = f
				}

			case "status-code":
				i, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					proxylib.ParseError(fmt.Sprintf("unable to parse status-code %s: %s", v, err), rule)
				} else {
					cr.statusCode = int(i)
				}

			case "delay-request":
				delay, err := time.ParseDuration(v)
				if err != nil {
					proxylib.ParseError(fmt.Sprintf("unable to parse delay-request duration %s: %s", v, err), rule)
				} else {
					logrus.Debugf("Setting delay to %v", delay)
					cr.delayRequest = delay
				}

			case "delay-response":
				delay, err := time.ParseDuration(v)
				if err != nil {
					proxylib.ParseError(fmt.Sprintf("unable to parse delay-response duration %s: %s", v, err), rule)
				} else {
					logrus.Debugf("Setting delay to %v", delay)
					cr.delayResponse = delay
				}

			case "rewrite-status":
				cr.rewriteStatus = v

			case "rewrite-body":
				cr.rewriteBody = v

			case "add-request-headers":
				if cr.addRequestHeaders == nil {
					cr.addRequestHeaders = map[string]string{}
				}
				for k, v := range parseKeyValueList(v) {
					cr.addRequestHeaders[k] = v
				}

			case "add-response-headers":
				if cr.addResponseHeaders == nil {
					cr.addResponseHeaders = map[string]string{}
				}
				for k, v := range parseKeyValueList(v) {
					cr.addResponseHeaders[k] = v
				}

			default:
				proxylib.ParseError(fmt.Sprintf("Unsupported rule key : %s", k), rule)
			}
		}

		logrus.Debugf("Parsed ChaosTestingRule : %v", cr)
		rules = append(rules, &cr)
	}
	return rules
}
