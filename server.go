package guerrilla

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/flashmob/go-guerrilla/backends"
	"github.com/flashmob/go-guerrilla/log"
	"github.com/flashmob/go-guerrilla/mail"
	"github.com/flashmob/go-guerrilla/mail/rfc5321"
	"github.com/flashmob/go-guerrilla/response"
	"github.com/flashmob/go-guerrilla/tls"
)

const (
	CommandVerbMaxLength = 16
	CommandLineMaxLength = 1024
	// Number of allowed unrecognized commands before we terminate the connection
	MaxUnrecognizedCommands = 5
)

const (
	// server has just been created
	ServerStateNew = iota
	// Server has just been stopped
	ServerStateStopped
	// Server has been started and is running
	ServerStateRunning
	// Server could not start due to an error
	ServerStateStartError
)

// Server listens for SMTP clients on the port specified in its config
type server struct {
	configStore     atomic.Value // stores guerrilla.ServerConfig
	tlsConfigStore  atomic.Value
	timeout         atomic.Value // stores time.Duration
	listenInterface string
	clientPool      *Pool
	wg              sync.WaitGroup // for waiting to shutdown
	listener        net.Listener
	closedListener  chan bool
	hosts           allowedHosts // stores map[string]bool for faster lookup
	state           int
	// If log changed after a config reload, newLogStore stores the value here until it's safe to change it
	logStore     atomic.Value
	mainlogStore atomic.Value
	backendStore atomic.Value
	envelopePool *mail.Pool
}

type allowedHosts struct {
	table      map[string]bool // host lookup table
	wildcards  []string        // host wildcard list (* is used as a wildcard)
	sync.Mutex                 // guard access to the map
}

type command []byte

var (
	cmdHELO     command = []byte("HELO")
	cmdEHLO     command = []byte("EHLO")
	cmdHELP     command = []byte("HELP")
	cmdXCLIENT  command = []byte("XCLIENT")
	cmdMAIL     command = []byte("MAIL FROM:")
	cmdRCPT     command = []byte("RCPT TO:")
	cmdRSET     command = []byte("RSET")
	cmdVRFY     command = []byte("VRFY")
	cmdNOOP     command = []byte("NOOP")
	cmdQUIT     command = []byte("QUIT")
	cmdDATA     command = []byte("DATA")
	cmdSTARTTLS command = []byte("STARTTLS")
	cmdAuth     command = []byte("AUTH LOGIN")
)

func (c command) match(in []byte) bool {
	return bytes.Index(in, []byte(c)) == 0
}

// Creates and returns a new ready-to-run Server from a configuration
func newServer(sc *ServerConfig, b backends.Backend, l log.Logger) (*server, error) {
	server := &server{
		clientPool:      NewPool(sc.MaxClients),
		closedListener:  make(chan bool, 1),
		listenInterface: sc.ListenInterface,
		state:           ServerStateNew,
		envelopePool:    mail.NewPool(sc.MaxClients),
	}
	server.logStore.Store(l)
	server.backendStore.Store(b)
	logFile := sc.LogFile
	if logFile == "" {
		// none set, use the same log file as mainlog
		logFile = server.mainlog().GetLogDest()
	}
	// set level to same level as mainlog level
	mainlog, logOpenError := log.GetLogger(logFile, server.mainlog().GetLevel())
	server.mainlogStore.Store(mainlog)
	if logOpenError != nil {
		server.log().WithError(logOpenError).Errorf("Failed creating a logger for server [%s]", sc.ListenInterface)
	}

	server.setConfig(sc)
	server.setTimeout(sc.Timeout)
	if err := server.configureSSL(); err != nil {
		return server, err
	}
	return server, nil
}

func (s *server) configureSSL() error {
	sConfig := s.configStore.Load().(ServerConfig)
	if sConfig.TLS.AlwaysOn || sConfig.TLS.StartTLSOn {
		cert, err := tls.LoadX509KeyPair(sConfig.TLS.PublicKeyFile, sConfig.TLS.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("error while loading the certificate: %s", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ServerName:   sConfig.Hostname,
		}
		if len(sConfig.TLS.Protocols) > 0 {
			if min, ok := TLSProtocols[sConfig.TLS.Protocols[0]]; ok {
				tlsConfig.MinVersion = min
			}
		}
		if len(sConfig.TLS.Protocols) > 1 {
			if max, ok := TLSProtocols[sConfig.TLS.Protocols[1]]; ok {
				tlsConfig.MaxVersion = max
			}
		}
		if len(sConfig.TLS.Ciphers) > 0 {
			for _, val := range sConfig.TLS.Ciphers {
				if c, ok := TLSCiphers[val]; ok {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, c)
				}
			}
		}
		if len(sConfig.TLS.Curves) > 0 {
			for _, val := range sConfig.TLS.Curves {
				if c, ok := TLSCurves[val]; ok {
					tlsConfig.CurvePreferences = append(tlsConfig.CurvePreferences, c)
				}
			}
		}
		if len(sConfig.TLS.RootCAs) > 0 {
			caCert, err := ioutil.ReadFile(sConfig.TLS.RootCAs)
			if err != nil {
				s.log().WithError(err).Errorf("failed opening TLSRootCAs file [%s]", sConfig.TLS.RootCAs)
			} else {
				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(caCert)
				tlsConfig.RootCAs = caCertPool
			}

		}
		if len(sConfig.TLS.ClientAuthType) > 0 {
			if ca, ok := TLSClientAuthTypes[sConfig.TLS.ClientAuthType]; ok {
				tlsConfig.ClientAuth = ca
			}
		}
		tlsConfig.PreferServerCipherSuites = sConfig.TLS.PreferServerCipherSuites
		tlsConfig.Rand = rand.Reader
		s.tlsConfigStore.Store(tlsConfig)
	}
	return nil
}

// setBackend sets the backend to use for processing email envelopes
func (s *server) setBackend(b backends.Backend) {
	s.backendStore.Store(b)
}

// backend gets the backend used to process email envelopes
func (s *server) backend() backends.Backend {
	if b, ok := s.backendStore.Load().(backends.Backend); ok {
		return b
	}
	return nil
}

// Set the timeout for the server and all clients
func (s *server) setTimeout(seconds int) {
	duration := time.Duration(int64(seconds))
	s.clientPool.SetTimeout(duration)
	s.timeout.Store(duration)
}

// goroutine safe config store
func (s *server) setConfig(sc *ServerConfig) {
	s.configStore.Store(*sc)
}

// goroutine safe
func (s *server) isEnabled() bool {
	sc := s.configStore.Load().(ServerConfig)
	return sc.IsEnabled
}

// Set the allowed hosts for the server
func (s *server) setAllowedHosts(allowedHosts []string) {
	s.hosts.Lock()
	defer s.hosts.Unlock()
	s.hosts.table = make(map[string]bool, len(allowedHosts))
	s.hosts.wildcards = nil
	for _, h := range allowedHosts {
		if strings.Index(h, "*") != -1 {
			s.hosts.wildcards = append(s.hosts.wildcards, strings.ToLower(h))
		} else {
			s.hosts.table[strings.ToLower(h)] = true
		}
	}
}

// Begin accepting SMTP clients. Will block unless there is an error or server.Shutdown() is called
func (s *server) Start(startWG *sync.WaitGroup) error {
	var clientID uint64
	clientID = 0

	listener, err := net.Listen("tcp", s.listenInterface)

	// Use proxy protocol listener if it is enabled
	sc := s.configStore.Load().(ServerConfig)
	if sc.ProxyProtocolOn {
		listener = &proxyproto.Listener{
			Listener: listener,
		}
	}

	s.listener = listener
	if err != nil {
		startWG.Done() // don't wait for me
		s.state = ServerStateStartError
		return fmt.Errorf("[%s] Cannot listen on port: %s ", s.listenInterface, err.Error())
	}

	s.log().Infof("Listening on TCP %s", s.listenInterface)
	s.state = ServerStateRunning
	startWG.Done() // start successful, don't wait for me

	for {
		s.log().Debugf("[%s] Waiting for a new client. Next Client ID: %d", s.listenInterface, clientID+1)
		conn, err := listener.Accept()
		clientID++
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				s.log().Infof("Server [%s] has stopped accepting new clients", s.listenInterface)
				// the listener has been closed, wait for clients to exit
				s.log().Infof("shutting down pool [%s]", s.listenInterface)
				s.clientPool.ShutdownState()
				s.clientPool.ShutdownWait()
				s.state = ServerStateStopped
				s.closedListener <- true
				return nil
			}
			s.mainlog().WithError(err).Info("Temporary error accepting client")
			continue
		}
		go func(p Poolable, borrowErr error) {
			c := p.(*client)
			if borrowErr == nil {
				s.handleClient(c)
				s.envelopePool.Return(c.Envelope)
				s.clientPool.Return(c)
			} else {
				s.log().WithError(borrowErr).Info("couldn't borrow a new client")
				// we could not get a client, so close the connection.
				_ = conn.Close()

			}
			// intentionally placed Borrow in args so that it's called in the
			// same main goroutine.
		}(s.clientPool.Borrow(conn, clientID, s.log(), s.envelopePool))

	}
}

func (s *server) Shutdown() {
	if s.listener != nil {
		// This will cause Start function to return, by causing an error on listener.Accept
		_ = s.listener.Close()
		// wait for the listener to listener.Accept
		<-s.closedListener
		// At this point Start will exit and close down the pool
	} else {
		s.clientPool.ShutdownState()
		// listener already closed, wait for clients to exit
		s.clientPool.ShutdownWait()
		s.state = ServerStateStopped
	}
}

func (s *server) GetActiveClientsCount() int {
	return s.clientPool.GetActiveClientsCount()
}

// Verifies that the host is a valid recipient.
// host checking turned off if there is a single entry and it's a dot.
func (s *server) allowsHost(host string) bool {
	s.hosts.Lock()
	defer s.hosts.Unlock()
	// if hosts contains a single dot, further processing is skipped
	if len(s.hosts.table) == 1 {
		if _, ok := s.hosts.table["."]; ok {
			return true
		}
	}
	if _, ok := s.hosts.table[strings.ToLower(host)]; ok {
		return true
	}
	// check the wildcards
	for _, w := range s.hosts.wildcards {
		if matched, err := filepath.Match(w, strings.ToLower(host)); matched && err == nil {
			return true
		}
	}
	return false
}

// Verifies the client passed the auth if the auth required
func (s *server) isAuthentication(authRequired bool, loginStatus bool) bool {
	return !(authRequired) || loginStatus
}

const commandSuffix = "\r\n"

// Reads from the client until a \n terminator is encountered,
// or until a timeout occurs.
func (s *server) readCommand(client *client) ([]byte, error) {
	//var input string
	var err error
	var bs []byte
	// In command state, stop reading at line breaks
	bs, err = client.bufin.ReadSlice('\n')
	if err != nil {
		return bs, err
	} else if bytes.HasSuffix(bs, []byte(commandSuffix)) {
		return bs[:len(bs)-2], err
	}
	return bs[:len(bs)-1], err
}

func (s *server) isShuttingDown() bool {
	return s.clientPool.IsShuttingDown()
}

// Handles an entire client SMTP exchange
func (s *server) handleClient(client *client) {
	defer client.closeConn()
	sc := s.configStore.Load().(ServerConfig)
	s.log().Debugf("Handle client [%s], id: %d", client.RemoteIP, client.ID)

	// Initial greeting
	greeting := fmt.Sprintf("220 %s UMBO SMTP #%d (%d) %s",
		sc.Hostname, client.ID,
		s.clientPool.GetActiveClientsCount(), time.Now().Format(time.RFC3339))

	helo := fmt.Sprintf("250 %s Hello", sc.Hostname)
	// ehlo is a multi-line reply and need additional \r\n at the end
	ehlo := fmt.Sprintf("250-%s Hello\r\n", sc.Hostname)

	// Extended feature advertisements
	messageSize := fmt.Sprintf("250-SIZE %d\r\n", sc.MaxSize)
	advertiseAuth := "250-AUTH LOGIN\r\n"
	pipelining := "250-PIPELINING\r\n"
	advertiseTLS := "250-STARTTLS\r\n"
	advertiseEnhancedStatusCodes := "250-ENHANCEDSTATUSCODES\r\n"
	// The last line doesn't need \r\n since string will be printed as a new line.
	// Also, Last line has no dash -
	help := "250 HELP"

	if sc.TLS.AlwaysOn {
		tlsConfig, ok := s.tlsConfigStore.Load().(*tls.Config)
		if !ok {
			s.mainlog().Error("Failed to load *tls.Config")
		} else if err := client.upgradeToTLS(tlsConfig); err == nil {
			advertiseTLS = ""
		} else {
			if strings.Contains(err.Error(), "SSLv2") {
				// we could ignore SSLv2 error because golang can't support it. Also reduce unnecessary error logs.
				s.log().WithError(err).Debug("[%s] Failed TLS handshake", client.RemoteIP)
			} else {
				s.log().WithError(err).Warn("[%s] Failed TLS handshake", client.RemoteIP)
			}
			// server requires TLS, but can't handshake
			client.kill()
		}
	}
	if !sc.TLS.StartTLSOn {
		// STARTTLS turned off, don't advertise it
		advertiseTLS = ""
	}
	r := response.Canned
	loginInfo := LoginInfo{
		status: false,
	}
	if client.isAlive() {
		err := client.sendResponse(s.timeout.Load().(time.Duration), greeting)
		if err != nil {
			s.log().WithError(err).Debug("error with response")
			return
		}
	}

	var cmdLogs []string

	for client.isAlive() {
		client.bufin.setLimit(CommandLineMaxLength)
		input, err := s.readCommand(client)
		s.log().Debugf("Client sent: %s", input)
		if err == io.EOF {
			s.log().WithError(err).Debugf("Client closed the connection: %s", client.RemoteIP)
			return
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			s.log().WithError(err).Warnf("Timeout: %s", client.RemoteIP)
			return
		} else if err == LineLimitExceeded {
			err := client.sendResponse(s.timeout.Load().(time.Duration), r.FailLineTooLong)
			if err != nil {
				s.log().WithError(err).Debug("error writing response")
			}
			client.kill()
			return
		} else if err != nil {
			s.log().WithError(err).Debugf("Read error: %s", client.RemoteIP)
			client.kill()
			return
		}
		if s.isShuttingDown() {
			s.handleShotdown(client, r)
			return
		}

		cmdLen := len(input)
		if cmdLen > CommandVerbMaxLength {
			cmdLen = CommandVerbMaxLength
		}
		cmd := bytes.ToUpper(input[:cmdLen])

		// keep SMTP command logs for debug purpose
		cmdLogs = append(cmdLogs, strings.Split(string(cmd), " ")[0])

		switch {
		case cmdHELO.match(cmd):
			client.Helo = string(bytes.Trim(input[4:], " "))
			client.resetTransaction()
			err = client.sendResponse(s.timeout.Load().(time.Duration), helo)
		case cmdEHLO.match(cmd):
			client.Helo = string(bytes.Trim(input[4:], " "))
			client.resetTransaction()
			err = client.sendResponse(s.timeout.Load().(time.Duration), ehlo,
				messageSize,
				advertiseAuth,
				pipelining,
				advertiseTLS,
				advertiseEnhancedStatusCodes,
				help,
			)
		case cmdHELP.match(cmd):
			quote := response.GetQuote()
			err = client.sendResponse(s.timeout.Load().(time.Duration), "214-OK\r\n", quote)
		case sc.XClientOn && cmdXCLIENT.match(cmd):
			if toks := bytes.Split(input[8:], []byte{' '}); len(toks) > 0 {
				for i := range toks {
					if vals := bytes.Split(toks[i], []byte{'='}); len(vals) == 2 {
						if bytes.Compare(vals[1], []byte("[UNAVAILABLE]")) == 0 {
							// skip
							continue
						}
						if bytes.Compare(vals[0], []byte("ADDR")) == 0 {
							client.RemoteIP = string(vals[1])
						}
						if bytes.Compare(vals[0], []byte("HELO")) == 0 {
							client.Helo = string(vals[1])
						}
					}
				}
			}
			err = client.sendResponse(s.timeout.Load().(time.Duration), r.SuccessMailCmd)
		case cmdMAIL.match(cmd):
			if !s.isAuthentication(sc.AuthenticationRequired, loginInfo.status) {
				err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailAuthRequired)
				break
			}
			if client.isInTransaction() {
				err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailNestedMailCmd)
				break
			}
			client.MailFrom, err = client.parsePath([]byte(input[10:]), client.parser.MailFrom)
			if err != nil {
				s.log().WithError(err).Error("MAIL parse error", "["+string(input[10:])+"]")
				err = client.sendResponse(s.timeout.Load().(time.Duration), err)
				break
			} else if client.parser.NullPath {
				// bounce has empty from address
				client.MailFrom = mail.Address{}
			}
			err = client.sendResponse(s.timeout.Load().(time.Duration), r.SuccessMailCmd)
		case cmdRCPT.match(cmd):
			if !s.isAuthentication(sc.AuthenticationRequired, loginInfo.status) {
				err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailAuthRequired)
				break
			}
			if len(client.RcptTo) > rfc5321.LimitRecipients {
				err = client.sendResponse(s.timeout.Load().(time.Duration), r.ErrorTooManyRecipients)
				break
			}
			to, err := client.parsePath([]byte(input[8:]), client.parser.RcptTo)
			if err != nil {
				s.log().WithError(err).Error("RCPT parse error", "["+string(input[8:])+"]")
				err = client.sendResponse(s.timeout.Load().(time.Duration), err.Error())
				break
			}
			if !s.allowsHost(to.Host) {
				err = client.sendResponse(s.timeout.Load().(time.Duration), r.ErrorRelayDenied, " ", to.Host)
			} else {
				client.PushRcpt(to)
				rcptError := s.backend().ValidateRcpt(client.Envelope)
				if rcptError != nil {
					client.PopRcpt()
					err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailRcptCmd, " ", rcptError.Error())
				} else {
					err = client.sendResponse(s.timeout.Load().(time.Duration), r.SuccessRcptCmd)
				}
			}
		case cmdRSET.match(cmd):
			client.resetTransaction()
			err = client.sendResponse(s.timeout.Load().(time.Duration), r.SuccessResetCmd)
		case cmdVRFY.match(cmd):
			err = client.sendResponse(s.timeout.Load().(time.Duration), r.SuccessVerifyCmd)
		case cmdNOOP.match(cmd):
			err = client.sendResponse(s.timeout.Load().(time.Duration), r.SuccessNoopCmd)
		case cmdQUIT.match(cmd):
			err = client.sendResponse(s.timeout.Load().(time.Duration), r.SuccessQuitCmd)
			client.kill()
		case cmdDATA.match(cmd):
			if !s.isAuthentication(sc.AuthenticationRequired, loginInfo.status) {
				err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailAuthRequired)
				if err != nil {
					s.log().WithError(err).Debug("error writing response")
					return
				}
				break
			}
			if len(client.RcptTo) == 0 {
				err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailNoRecipientsDataCmd)
				break
			}
			err = client.sendResponse(s.timeout.Load().(time.Duration), r.SuccessDataCmd)
			if err != nil {
				break
			}
			client.CmdLogs = cmdLogs
			err = s.handleData(client, sc, r)
			if err != nil {
				break
			}
		case cmdAuth.match(cmd):
			if loginInfo.status == true {
				err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailNoIdentityChangesPermitted)
				break
			}

			client.Envelope.AuthBeginAt = time.Now().UTC()
			cmds := strings.Split(string(input), " ")
			if len(cmds) > 2 {
				l, err := s.handleAuthWithUsername(client, cmds[2], r)
				if err != nil {
					err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailAuthNotAccepted)
					break
				}
				loginInfo = l
			} else {
				l, err := s.handleAuth(client, r)
				if err != nil {
					break
				}
				loginInfo = l
			}
			client.Envelope.AuthEndAt = time.Now().UTC()

		case sc.TLS.StartTLSOn && cmdSTARTTLS.match(cmd):
			err = client.sendResponse(s.timeout.Load().(time.Duration), r.SuccessStartTLSCmd)
			if err != nil {
				return
			}
			if s.handleStartTLS(client, sc) {
				advertiseTLS = ""
			}
		default:
			client.errors++
			if client.errors >= MaxUnrecognizedCommands {
				err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailMaxUnrecognizedCmd)
				client.kill()
			} else {
				err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailUnrecognizedCmd)
			}
		}
		if err != nil {
			s.log().WithError(err).Debug("error with response")
			return
		}
	}
}

func (s *server) handleStartTLS(client *client, sc ServerConfig) (successful bool) {
	if !client.TLS && sc.TLS.StartTLSOn {
		tlsConfig, ok := s.tlsConfigStore.Load().(*tls.Config)
		if !ok {
			s.mainlog().Error("Failed to load *tls.Config")
		} else if err := client.upgradeToTLS(tlsConfig); err == nil {
			client.resetTransaction()
		} else {
			if strings.Contains(err.Error(), "SSLv2") {
				// we could ignore SSLv2 error because golang can't support it. Also reduce unnecessary error logs.
				s.log().WithError(err).Debug("[%s] Failed TLS handshake", client.RemoteIP)
			} else {
				s.log().WithError(err).Warn("[%s] Failed TLS handshake", client.RemoteIP)
			}
			// Don't disconnect, let the client decide if it wants to continue
		}
	}
	return
}

func (s *server) handleShotdown(client *client, r response.Responses) {
	if err := client.sendResponse(s.timeout.Load().(time.Duration), r.ErrorShutdown); err != nil {
		s.log().WithError(err).Debug("error writing response")
		return
	}
	client.kill()
}

func (s *server) handleData(client *client, sc ServerConfig, r response.Responses) (err error) {
	// intentionally placed the limit 1MB above so that reading does not return with an error
	// if the client goes a little over. Anything above will err
	client.bufin.setLimit(int64(sc.MaxSize) + 1024000) // This a hard limit.

	client.Envelope.DataBeginAt = time.Now().UTC()

	n, err := client.Data.ReadFrom(client.smtpReader.DotReader())
	if n > sc.MaxSize {
		err = fmt.Errorf("maximum DATA size exceeded (%d)", sc.MaxSize)
	}
	if err != nil {
		s.log().WithError(err).Warn("Error reading data")
		if err == LineLimitExceeded {
			err = client.sendResponse(
				s.timeout.Load().(time.Duration),
				r.FailReadLimitExceededDataCmd, " ",
				LineLimitExceeded.Error())
			client.kill()
		} else if err == MessageSizeExceeded {
			err = client.sendResponse(
				s.timeout.Load().(time.Duration),
				r.FailMessageSizeExceeded, " ",
				MessageSizeExceeded.Error())
			client.kill()
		} else {
			err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailReadErrorDataCmd, " ", err.Error())
			client.kill()
		}
		client.resetTransaction()
		return
	}

	client.Envelope.DataEndAt = time.Now().UTC()

	res := s.backend().Process(client.Envelope)
	if res.Code() < 300 {
		client.messagesSent++
	}
	err = client.sendResponse(s.timeout.Load().(time.Duration), res)
	if err != nil {
		return
	}
	if s.isShuttingDown() {
		s.handleShotdown(client, r)
	}
	client.resetTransaction()
	return
}

func (s *server) handleAuth(client *client, r response.Responses) (loginInfo LoginInfo, err error) {
	// Send status code and base64 encode Username:
	err = client.sendResponse(s.timeout.Load().(time.Duration), "334 VXNlcm5hbWU6")
	if err != nil {
		return LoginInfo{}, err
	}

	// Read the username from client
	username, err := client.authReader.ReadLine()
	if err != nil {
		return LoginInfo{}, err
	}
	bsUsername, err := base64.StdEncoding.DecodeString(username)
	if err != nil {
		return LoginInfo{}, err
	}
	loginInfo.username = string(bsUsername)

	// Send status code and the base64 encoded Password
	err = client.sendResponse(s.timeout.Load().(time.Duration), "334 UGFzc3dvcmQ6")
	if err != nil {
		return LoginInfo{}, err
	}

	// Read the password from client
	password, err := client.authReader.ReadLine()
	if err != nil {
		return LoginInfo{}, err
	}
	bsPassword, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		return LoginInfo{}, err
	}
	loginInfo.password = string(bsPassword)
	// Validate the username and password from validate function
	values, err := Authentication.Validate(&loginInfo)
	if err != nil {
		err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailAuthNotAccepted)
		return LoginInfo{}, err
	}

	// Put username and password into Account
	client.Account.Username = loginInfo.username
	client.Account.Password = loginInfo.password

	for key, v := range values {
		if key != "" && v != nil {
			client.Values[key] = v
		}
	}

	loginInfo.status = true
	err = client.sendResponse(s.timeout.Load().(time.Duration), r.SuccessAuthentication)
	if err != nil {
		return LoginInfo{}, err
	}
	return loginInfo, nil
}

func (s *server) handleAuthWithUsername(
	client *client,
	username string,
	r response.Responses,
) (loginInfo LoginInfo, err error) {
	// Read the username from client
	bsUsername, err := base64.StdEncoding.DecodeString(username)
	if err != nil {
		return LoginInfo{}, err
	}
	loginInfo.username = string(bsUsername)

	// Send status code and the base64 encoded Password
	err = client.sendResponse(s.timeout.Load().(time.Duration), "334 UGFzc3dvcmQ6")
	if err != nil {
		return LoginInfo{}, err
	}

	// Read the password from client
	password, err := client.authReader.ReadLine()
	if err != nil {
		return LoginInfo{}, err
	}
	bsPassword, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		return LoginInfo{}, err
	}
	loginInfo.password = string(bsPassword)
	// Validate the username and password from validate function
	values, err := Authentication.Validate(&loginInfo)
	if err != nil {
		err = client.sendResponse(s.timeout.Load().(time.Duration), r.FailAuthNotAccepted)
		return LoginInfo{}, err
	}

	// Put username and password into Account
	client.Account.Username = loginInfo.username
	client.Account.Password = loginInfo.password

	for key, v := range values {
		if key != "" && v != nil {
			client.Values[key] = v
		}
	}
	loginInfo.status = true

	err = client.sendResponse(s.timeout.Load().(time.Duration), r.SuccessAuthentication)
	if err != nil {
		return LoginInfo{}, err
	}
	return loginInfo, nil
}

func (s *server) log() log.Logger {
	if l, ok := s.logStore.Load().(log.Logger); ok {
		return l
	}
	l, err := log.GetLogger(log.OutputStderr.String(), log.InfoLevel.String())
	if err == nil {
		s.logStore.Store(l)
	}
	return l
}

func (s *server) mainlog() log.Logger {
	if l, ok := s.mainlogStore.Load().(log.Logger); ok {
		return l
	}
	l, err := log.GetLogger(log.OutputStderr.String(), log.InfoLevel.String())
	if err == nil {
		s.mainlogStore.Store(l)
	}
	return l
}
