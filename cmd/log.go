// Copyright © 2018 Pinpoint (PinPT, Inc)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	r "runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/spf13/cobra"
)

// Getenv will return an environment variable if exists or default if not
func Getenv(name, def string) string {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	return v
}

// Stringify will return a JSON formatted string. pass an optional second argument to pretty print
func Stringify(v interface{}, opts ...interface{}) string {
	var buf bytes.Buffer
	dec := json.NewEncoder(&buf)
	if len(opts) > 0 {
		dec.SetIndent("", "\t")
	}
	if err := dec.Encode(v); err != nil {
		return fmt.Sprintf("<error:%v>", err)
	}
	// by default will add \n, but for this function we're going to trim it
	slice := buf.Bytes()
	return string(slice[0 : len(slice)-1])
}

// HashValues will convert all objects to a string and return a SHA256 of the concatenated values
func HashValues(objects ...interface{}) string {
	h := sha256.New()
	for _, o := range objects {
		if s, ok := o.(string); ok {
			io.WriteString(h, s)
		} else {
			if s, ok := o.(*string); ok {
				io.WriteString(h, *s)
			} else {
				if b, ok := o.([]byte); ok {
					h.Write(b)
					continue
				}
				if n, ok := o.(int); ok {
					io.WriteString(h, fmt.Sprintf("%d", n))
					continue
				}
				if n, ok := o.(int32); ok {
					io.WriteString(h, fmt.Sprintf("%d", n))
					continue
				}
				if n, ok := o.(int64); ok {
					io.WriteString(h, fmt.Sprintf("%d", n))
					continue
				}
				if n, ok := o.(float32); ok {
					io.WriteString(h, fmt.Sprintf("%f", n))
					continue
				}
				if n, ok := o.(float64); ok {
					io.WriteString(h, fmt.Sprintf("%f", n))
					continue
				}
				if n, ok := o.(bool); ok {
					io.WriteString(h, fmt.Sprintf("%v", n))
					continue
				}
				if n, ok := o.(*int); ok {
					if n == nil {
						io.WriteString(h, "")
					} else {
						io.WriteString(h, fmt.Sprintf("%d", *n))
					}
					continue
				}
				if n, ok := o.(*int32); ok {
					if n == nil {
						io.WriteString(h, "")
					} else {
						io.WriteString(h, fmt.Sprintf("%d", *n))
					}
					continue
				}
				if n, ok := o.(*int64); ok {
					if n == nil {
						io.WriteString(h, "")
					} else {
						io.WriteString(h, fmt.Sprintf("%d", *n))
					}
					continue
				}
				if n, ok := o.(*float32); ok {
					if n == nil {
						io.WriteString(h, "")
					} else {
						io.WriteString(h, fmt.Sprintf("%f", *n))
					}
					continue
				}
				if n, ok := o.(*float64); ok {
					if n == nil {
						io.WriteString(h, "")
					} else {
						io.WriteString(h, fmt.Sprintf("%f", *n))
					}
					continue
				}
				if n, ok := o.(*bool); ok {
					if n == nil {
						io.WriteString(h, "")
					} else {
						io.WriteString(h, fmt.Sprintf("%v", n))
					}
					continue
				}
				io.WriteString(h, fmt.Sprintf("%v", o))
			}
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Info log helper
func Info(logger log.Logger, msg string, kv ...interface{}) error {
	a := []interface{}{msgKey, msg}
	if kv != nil {
		a = append(a, kv...)
	}
	return level.Info(logger).Log(a...)
}

// Debug log helper
func Debug(logger log.Logger, msg string, kv ...interface{}) error {
	a := []interface{}{msgKey, msg}
	if kv != nil {
		a = append(a, kv...)
	}
	return level.Debug(logger).Log(a...)
}

// Warn log helper
func Warn(logger log.Logger, msg string, kv ...interface{}) error {
	a := []interface{}{msgKey, msg}
	if kv != nil {
		a = append(a, kv...)
	}
	return level.Warn(logger).Log(a...)
}

// Error log helper
func Error(logger log.Logger, msg string, kv ...interface{}) error {
	a := []interface{}{msgKey, msg}
	if kv != nil {
		a = append(a, kv...)
	}
	return level.Error(logger).Log(a...)
}

// Fatal log helper
func Fatal(logger log.Logger, msg string, kv ...interface{}) {
	a := []interface{}{msgKey, msg}
	if kv != nil {
		a = append(a, kv...)
	}
	level.Error(logger).Log(a...)
	os.Exit(1)
}

type consoleLogger struct {
	w     io.Writer
	pkg   string
	theme LogColorTheme
}

var (
	infoColor     = color.New(color.FgGreen)
	errColor      = color.New(color.FgRed)
	debugColor    = color.New(color.FgBlue)
	pkgColor      = color.New(color.FgHiMagenta)
	msgColor      = color.New(color.FgWhite).Add(color.Bold)
	msgLightColor = color.New(color.FgBlack).Add(color.Bold)
	kvColor       = color.New(color.FgYellow)

	termMu       = sync.RWMutex{}
	termWidth    = 120
	ansiStripper = regexp.MustCompile("\\x1b\\[[0-9;]*m")
)

const (
	pkgKey = "pkg"
	msgKey = "msg"
	tsKey  = "ts"
)

var (
	levelKey      = fmt.Sprintf("%v", level.Key())
	debugLevel    = level.DebugValue().String()
	warnLevel     = level.WarnValue().String()
	errLevel      = level.ErrorValue().String()
	infoLevel     = level.InfoValue().String()
	customerIDKey = "customer_id"
	onprem        = os.Getenv("PP_CUSTOMER_ID") != ""
)

func (l *consoleLogger) Log(keyvals ...interface{}) error {
	n := (len(keyvals) + 1) / 2 // +1 to handle case when len is odd
	m := make(map[string]interface{}, n)
	m[pkgKey] = l.pkg
	keys := make([]string, 0)
	for i := 0; i < len(keyvals); i += 2 {
		k := keyvals[i]
		if s, ok := k.(string); ok {
			if s[0:1] == "$" {
				// for the console, we're going to ignore internal keys
				continue
			}
			if onprem && s == customerIDKey {
				// for onpremise env, don't show customer_id to the console
				continue
			}
		}
		var v interface{} = log.ErrMissingValue
		if i+1 < len(keyvals) {
			v = keyvals[i+1]
		}
		merge(m, k, v)
		keys = append(keys, fmt.Sprintf("%v", k))
	}
	hasColors := !color.NoColor && l.theme != NoColorTheme
	lvl := fmt.Sprintf("%v", m[levelKey])
	var c *color.Color
	if hasColors {
		switch lvl {
		case debugLevel:
			{
				c = debugColor
			}
		case warnLevel, errLevel:
			{
				c = errColor
			}
		default:
			{
				lvl = infoLevel
				c = infoColor
			}
		}
	}
	if m[pkgKey] == nil {
		m[pkgKey] = "unset"
	}
	pkg := m[pkgKey].(string)
	if len(pkg) > 7 {
		pkg = pkg[0:7]
	}
	kv := make([]string, 0)
	var msg string
	if ms, ok := m[msgKey].(string); ok {
		msg = ansiStripper.ReplaceAllString(ms, "")
	} else {
		msg = fmt.Sprintf("%v", m[msgKey])
	}
	left := len(msg) + 7 + 10
	slen := 0
	scnt := 0
	sort.Strings(keys)
	for _, k := range keys {
		switch k {
		case levelKey, pkgKey, tsKey, msgKey:
			{
				continue
			}
		}
		v := m[k]
		k = ansiStripper.ReplaceAllString(k, "")
		val := ansiStripper.ReplaceAllString(strings.TrimSpace(fmt.Sprintf("%v", v)), "")
		slen += 1 + len(k) + len(val)
		scnt++
		if hasColors {
			kv = append(kv, fmt.Sprintf("%s=%s", kvColor.Sprint(k), kvColor.Sprint(val)))
		} else {
			kv = append(kv, fmt.Sprintf("%s=%s", k, val))
		}
	}
	var kvs string
	termMu.RLock()
	pad := int(termWidth) - left
	termMu.RUnlock()
	slen += scnt - 1
	if len(kv) > 0 {
		kvs = strings.Join(kv, " ")
		var buf bytes.Buffer
		for i := 0; i < pad-slen; i++ {
			buf.WriteByte(' ')
		}
		buf.WriteString(kvs)
		kvs = buf.String()
	}
	if color.NoColor {
		fmt.Fprintf(l.w, "%s %s %s %s\n", fmt.Sprintf("%-6s", strings.ToUpper(lvl)), fmt.Sprintf("%-8s", pkg), msg, kvs)
	} else {
		mc := msgColor
		if l.theme == LightLogColorTheme {
			mc = msgLightColor
		}
		fmt.Fprintf(l.w, "%s %s %s %s\n", c.Sprintf("%-6s", strings.ToUpper(lvl)), pkgColor.Sprintf("%-8s", pkg), mc.Sprint(msg), kvs)
	}
	return nil
}

func merge(dst map[string]interface{}, k, v interface{}) {
	var key string
	switch x := k.(type) {
	case string:
		key = x
	case fmt.Stringer:
		key = safeString(x)
	default:
		key = fmt.Sprint(x)
	}

	// We want json.Marshaler and encoding.TextMarshaller to take priority over
	// err.Error() and v.String(). But json.Marshall (called later) does that by
	// default so we force a no-op if it's one of those 2 case.
	switch x := v.(type) {
	case json.Marshaler:
	case encoding.TextMarshaler:
	case error:
		v = safeError(x)
	case fmt.Stringer:
		v = safeString(x)
	}

	dst[key] = v
}

func safeString(str fmt.Stringer) (s string) {
	defer func() {
		if panicVal := recover(); panicVal != nil {
			if v := reflect.ValueOf(str); v.Kind() == reflect.Ptr && v.IsNil() {
				s = "NULL"
			} else {
				panic(panicVal)
			}
		}
	}()
	s = str.String()
	return
}

func safeError(err error) (s interface{}) {
	defer func() {
		if panicVal := recover(); panicVal != nil {
			if v := reflect.ValueOf(err); v.Kind() == reflect.Ptr && v.IsNil() {
				s = nil
			} else {
				panic(panicVal)
			}
		}
	}()
	s = err.Error()
	return
}

// LogOutputFormat is the logging output format
type LogOutputFormat byte

const (
	// JSONLogFormat will output JSON formatted logs
	JSONLogFormat LogOutputFormat = 1 << iota
	// LogFmtLogFormat will output logfmt formatted logs
	LogFmtLogFormat
	// ConsoleLogFormat will output logfmt colored logs to console
	ConsoleLogFormat
)

// LogColorTheme is the logging color theme
type LogColorTheme byte

const (
	// DarkLogColorTheme is the default color theme for console logging (if enabled)
	DarkLogColorTheme LogColorTheme = 1 << iota
	// LightLogColorTheme is for consoles that are light (vs dark)
	LightLogColorTheme
	// NoColorTheme will turn off console colors
	NoColorTheme
)

// LogLevel is the minimum logging level
type LogLevel byte

const (
	// InfoLevel will only log level and above (default)
	InfoLevel LogLevel = 1 << iota
	// DebugLevel will log all messages
	DebugLevel
	// WarnLevel will only log warning and above
	WarnLevel
	// ErrorLevel will only log error and above
	ErrorLevel
	// NoneLevel will no log at all
	NoneLevel
)

// LevelFromString will return a LogLevel const from a named string
func LevelFromString(level string) LogLevel {
	switch level {
	case "info", "INFO", "":
		{
			return InfoLevel
		}
	case "debug", "DEBUG":
		{
			return DebugLevel
		}
	case "warn", "WARN", "warning", "WARNING":
		{
			return WarnLevel
		}
	case "error", "ERROR", "fatal", "FATAL":
		{
			return ErrorLevel
		}
	}
	return NoneLevel
}

// LoggerCloser returns a logger which implements a Close interface
type LoggerCloser interface {
	log.Logger
	Close() error
}

type logcloser struct {
	w io.WriteCloser
	l log.Logger
	o sync.Once
}

// Log will dispatch the log to the next logger
func (l *logcloser) Log(kv ...interface{}) error {
	return l.l.Log(kv...)
}

// Close will close the underlying writer
func (l *logcloser) Close() error {
	l.o.Do(func() {
		// don't close the main process stdout/stderr
		if l.w == os.Stdout || l.w == os.Stderr {
			return
		}
		l.w.Close()
	})
	return nil
}

type nocloselog struct {
	l log.Logger
}

// Log will dispatch the log to the next logger
func (l *nocloselog) Log(kv ...interface{}) error {
	return l.l.Log(kv...)
}

// Close will close the underlying writer
func (l *nocloselog) Close() error {
	return nil
}

// WithLogOptions is a callback for customizing the logger event further before returning
type WithLogOptions func(logger log.Logger) log.Logger

// WithDefaultTimestampLogOption will add the timestamp in UTC to the ts key
func WithDefaultTimestampLogOption() WithLogOptions {
	return func(logger log.Logger) log.Logger {
		return log.With(logger, tsKey, log.DefaultTimestampUTC)
	}
}

type oklogger struct {
	u    []*url.URL
	next log.Logger
	ch   chan string
}

var oklogIgnoreKeys = map[interface{}]bool{"caller": true}

// Log will dispatch the log to the next logger
func (l *oklogger) Log(keyvals ...interface{}) error {
	l.next.Log(keyvals...)

	// JSON encode it to the channel
	n := (len(keyvals) + 1) / 2 // +1 to handle case when len is odd
	m := make(map[string]interface{}, n)
	for i := 0; i < len(keyvals); i += 2 {
		k := keyvals[i]
		if oklogIgnoreKeys[k] {
			continue
		}
		var v interface{} = log.ErrMissingValue
		if i+1 < len(keyvals) {
			v = keyvals[i+1]
		}
		merge(m, k, v)
	}
	s := Stringify(m)
	// if we can't stringify, don't send it
	if !strings.HasPrefix(s, "<error:") {
		l.ch <- s
	}
	return nil
}

// Close will close the underlying channel
func (l *oklogger) Close() error {
	close(l.ch)
	return nil
}

func (l *oklogger) run() {
	go func() {
		var attempts uint
		lf := byte('\n')
		rand.Seed(time.Now().UnixNano())
		for i := range l.u {
			j := rand.Intn(i + 1)
			l.u[i], l.u[j] = l.u[j], l.u[i]
		}
		for {
			// rotate thru URLs
			l.u = append(l.u[1:], l.u[0])
			u := l.u[0]
			conn, err := net.Dial(u.Scheme, u.Host)
			if err != nil {
				time.Sleep(time.Millisecond * (50 * time.Duration(attempts)))
				attempts++
				continue
			}
			attempts = 0
			empty := true
			for buf := range l.ch {
				// don't send empty strings
				if len(buf) == 0 || buf[0] == lf {
					continue
				}
				n, err := fmt.Fprintln(conn, buf)
				if n < 0 || err != nil {
					empty = false
					break
				}
			}
			if !empty {
				conn.Close()
				conn = nil
				continue
			}
			conn.Close()
			break
		}
	}()
}

// WithOKLogForwarder will attempt to send logs to OKLog
func WithOKLogForwarder(u []*url.URL) WithLogOptions {
	return func(logger log.Logger) log.Logger {
		ch := make(chan string, 1000)
		l := &oklogger{
			u,
			logger,
			ch,
		}
		l.run()
		return log.With(l, tsKey, log.DefaultTimestampUTC)
	}
}

// NewNoOpTestLogger is a test logger that doesn't log at all
func NewNoOpTestLogger() LoggerCloser {
	return &nocloselog{level.NewFilter(log.NewLogfmtLogger(os.Stderr), level.AllowError())}
}

type maskingLogger struct {
	next log.Logger
}

var maskedKeys = map[string]bool{
	"password":   true,
	"email":      true,
	"access_key": true,
	"secret":     true,
	"passwd":     true,
}

var maskedPattern = regexp.MustCompile("(?i)password")

func mask(v interface{}) interface{} {
	if s, ok := v.(string); ok {
		l := len(s)
		if l == 0 {
			return s
		}
		if l == 1 {
			return "*"
		}
		h := int(l / 2)
		var buf bytes.Buffer
		buf.WriteString(s[0:h])
		buf.WriteString(strings.Repeat("*", l-h))
		return buf.String()
	}
	return v
}

func (l *maskingLogger) Log(keyvals ...interface{}) error {
	// we have to make a copy as to not have a race
	newvals := append([]interface{}{}, keyvals...)
	for i := 0; i < len(newvals); i += 2 {
		k := newvals[i]
		var v interface{} = log.ErrMissingValue
		if i+1 < len(newvals) {
			v = newvals[i+1]
		}
		if s, ok := k.(string); ok && v != log.ErrMissingValue {
			if maskedKeys[s] || maskedPattern.MatchString(s) {
				nv := mask(v)
				if nv != v {
					newvals[i+1] = nv
				}
			}
		}
	}
	return l.next.Log(newvals...)
}

// newMaskingLogger returns a logger that will attempt to mask certain sensitive
// details
func newMaskingLogger(logger log.Logger) *maskingLogger {
	return &maskingLogger{logger}
}

// dedupelogger will de-dupe the keys (LIFO) excluding msg, level, etc
// such that we only emit one unique key per log message
type dedupelogger struct {
	next log.Logger
}

func (l *dedupelogger) Log(keyvals ...interface{}) error {
	newvals := make([]interface{}, 0)
	var kvs map[string]interface{}
	for i := 0; i < len(keyvals); i += 2 {
		k := keyvals[i]
		var v interface{} = log.ErrMissingValue
		if i+1 < len(keyvals) {
			v = keyvals[i+1]
		}
		if k == msgKey || k == levelKey {
			newvals = append(newvals, k, v)
		} else {
			if kvs == nil {
				kvs = make(map[string]interface{})
			}
			kvs[fmt.Sprintf("%s", k)] = v
		}
	}
	if kvs != nil && len(kvs) > 0 {
		var i int
		keys := make([]string, len(kvs))
		for k := range kvs {
			keys[i] = k
			i++
		}
		sort.Strings(keys)
		for _, k := range keys {
			newvals = append(newvals, k, kvs[k])
		}
	}
	return l.next.Log(newvals...)
}

// track the depth from which the call stack should track the call site
const callStackDepth = 9

// NewLogger will create a new logger
func NewLoggerUtil(writer io.Writer, format LogOutputFormat, theme LogColorTheme, minLevel LogLevel, pkg string, opts ...WithLogOptions) LoggerCloser {
	// short circuit it all if log level is none
	if minLevel == NoneLevel {
		return &nocloselog{log.NewNopLogger()}
	}

	var logger log.Logger

	switch format {
	case JSONLogFormat:
		{
			logger = log.NewJSONLogger(writer)
		}
	case LogFmtLogFormat:
		{
			logger = log.NewLogfmtLogger(writer)
		}
	case ConsoleLogFormat:
		{
			logger = &consoleLogger{writer, pkg, theme}
		}
	}

	// allow any functions to transform the logger further before we return
	if opts != nil {
		for _, o := range opts {
			logger = o(logger)
		}
	}

	logger = log.With(logger, pkgKey, pkg)

	// turn off caller for test package
	allowCaller := pkg != "test"

	switch minLevel {
	case DebugLevel:
		{
			logger = level.NewFilter(logger, level.AllowDebug())
			if allowCaller {
				logger = log.With(logger, "caller", log.Caller(callStackDepth))
			}
		}
	case InfoLevel:
		{
			logger = level.NewFilter(logger, level.AllowInfo())
		}
	case ErrorLevel:
		{
			logger = level.NewFilter(logger, level.AllowError())
			if allowCaller {
				logger = log.With(logger, "caller", log.Caller(callStackDepth))
			}
		}
	case WarnLevel:
		{
			logger = level.NewFilter(logger, level.AllowWarn())
		}
	}

	// create a masking logger
	logger = newMaskingLogger(logger)

	// make sure that all message have a level
	logger = level.NewInjector(logger, level.InfoValue())

	// make sure we de-dupe log keys
	logger = &dedupelogger{logger}

	// if the writer implements the io.WriteCloser we wrap the
	// return value in a write closer interface
	if w, ok := writer.(io.WriteCloser); ok {
		return &logcloser{w, logger, sync.Once{}}
	}

	// wrap in a type that suppresses the call to Close
	return &nocloselog{logger}
}

const dockerCGroup = "/proc/self/cgroup"
const k8sServiceAcct = "/var/run/secrets/kubernetes.io/serviceaccount"

// NewLogger returns a new log.Logger for a given command
func NewLogger(cmd *cobra.Command, pkg string) log.Logger {
	var isContainer bool
	if r.GOOS == "linux" {
		if FileExists(dockerCGroup) {
			buf, err := ioutil.ReadFile(dockerCGroup)
			if err != nil && bytes.Contains(buf, []byte("docker")) {
				isContainer = true
			}
		} else if FileExists(k8sServiceAcct) {
			isContainer = true
		}
	}

	var writer io.Writer
	var isfile bool
	o, _ := cmd.Flags().GetString("log-output")
	switch o {
	case "-":
		{
			writer = os.Stdout
			if isContainer {
				// for docker, we want to log to /dev/stderr
				writer = os.Stderr
			}
		}
	case "/dev/stdout", "stdout":
		{
			writer = os.Stdout
		}
	case "/dev/stderr", "stderr":
		{
			writer = os.Stderr
		}
	case "/dev/null":
		{
			writer = ioutil.Discard
		}
	default:
		{
			// write to a file
			f, err := os.Create(o)
			if err != nil {
				fmt.Printf("Cannot open %s. %v\n", o, err)
				os.Exit(1)
			}
			w := os.Stdout
			if isContainer {
				w = os.Stderr
			}
			// write to both the normal output as well as the file
			writer = io.MultiWriter(f, w)
			isfile = true
		}
	}
	var logFormat LogOutputFormat
	lf, _ := cmd.Flags().GetString("log-format")
	switch lf {
	case "json":
		{
			logFormat = JSONLogFormat
		}
	case "logfmt":
		{
			logFormat = LogFmtLogFormat
		}
	default:
		{
			if isfile {
				logFormat = LogFmtLogFormat
			} else {
				logFormat = ConsoleLogFormat
			}
		}
	}

	var logColorTheme LogColorTheme
	lc, _ := cmd.Flags().GetString("log-color")
	switch lc {
	case "light":
		{
			logColorTheme = LightLogColorTheme
		}
	case "none":
		{
			logColorTheme = NoColorTheme
			color.NoColor = true
		}
	default:
		{
			if color.NoColor {
				logColorTheme = NoColorTheme
			} else {
				logColorTheme = DarkLogColorTheme
			}
		}
	}

	var minLogLevel LogLevel
	lvl, _ := cmd.Flags().GetString("log-level")
	switch strings.ToLower(lvl) {
	case "debug":
		{
			minLogLevel = DebugLevel
		}
	case "info":
		{
			minLogLevel = InfoLevel
		}
	case "error":
		{
			minLogLevel = ErrorLevel
		}
	case "warn", "warning":
		{
			minLogLevel = WarnLevel
		}
	case "none":
		{
			minLogLevel = NoneLevel
		}
	default:
		{
			minLogLevel = InfoLevel
		}
	}

	// if discard writer, optimize the return
	if writer == ioutil.Discard {
		minLogLevel = NoneLevel
	}

	var opts []WithLogOptions

	if isContainer || isfile {
		// if inside docker or in a file, we want timestamp
		opts = []WithLogOptions{
			WithDefaultTimestampLogOption(),
		}
	}

	// if running inside kubernetes, add special keys for this deployment/pod/container
	if os.Getenv("PP_K8S_NAMESPACE") != "" {
		if opts == nil {
			opts = make([]WithLogOptions, 0)
		}
		opts = append(opts, WithLogOptions(func(logger log.Logger) log.Logger {
			return log.With(logger,
				"$ns", os.Getenv("PP_K8S_NAMESPACE"),
				"$svc", os.Getenv("PP_K8S_SERVICE"),
				"$dpy", os.Getenv("PP_K8S_RELEASE"),
				"$node", os.Getenv("PP_K8S_NODE"),
				"$pod", os.Getenv("PP_K8S_POD"),
			)
		}))
	}

	logServers, _ := cmd.Flags().GetStringSlice("log-ingestion")
	if logServers == nil || len(logServers) == 0 {
		// check the environment and if we have a hostname, form a url list
		hostname := os.Getenv("PP_OKLOG_HOSTNAME")
		if hostname != "" {
			url := fmt.Sprintf("tcp://%s:7651", hostname)
			// create multiple since they are k8s services likely
			logServers = []string{url, url, url}
		}
	}
	if logServers != nil && len(logServers) > 0 {
		if opts == nil {
			opts = make([]WithLogOptions, 0)
		}
		urls := make([]*url.URL, 0)
		for _, s := range logServers {
			u, err := url.Parse(s)
			if err != nil {
				fmt.Printf("ERROR parsing log-ingestion url %s. %v\n", s, err)
				os.Exit(1)
			}
			urls = append(urls, u)
		}
		opts = append(opts, WithOKLogForwarder(urls))
	}

	return NewLoggerUtil(writer, logFormat, logColorTheme, minLogLevel, pkg, opts...)
}
