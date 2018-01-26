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
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	k "github.com/ericchiang/k8s"
	"github.com/spf13/cobra"
)

// Resolve with resolve a relative file path
func Resolve(filename string) (string, error) {
	if filename == "" {
		return filename, fmt.Errorf("filename was not supplied")
	}
	f, err := filepath.Abs(filename)
	if err != nil {
		return filename, err
	}
	_, err = os.Stat(f)
	if os.IsNotExist(err) {
		return f, err
	}
	return f, err
}

// FileExists returns true if the path components exist
func FileExists(filename ...string) bool {
	fn := filepath.Join(filename...)
	fn, err := Resolve(fn)
	if err != nil {
		return false
	}
	return true
}

func sigHandler(pid int, signalChannel chan os.Signal) {
	var sigToSend = syscall.SIGHUP
	for {
		sig := <-signalChannel
		switch sig {
		// Sent went the controlling terminal is closed, typically used
		// by daemonised processes to reload config
		case syscall.SIGHUP:
			sigToSend = syscall.SIGHUP
		// Like pressing CTRL+C
		case syscall.SIGINT:
			sigToSend = syscall.SIGINT
		// Core Dump
		case syscall.SIGQUIT:
			sigToSend = syscall.SIGQUIT
		// Invalid instruction
		case syscall.SIGILL:
			sigToSend = syscall.SIGILL
		// A debugger wants to know something has happened
		case syscall.SIGTRAP:
			sigToSend = syscall.SIGTRAP
		// Usually when a process itself calls abort()
		case syscall.SIGABRT:
			sigToSend = syscall.SIGABRT
		// Die immediately, can not be ignored
		case syscall.SIGKILL:
			sigToSend = syscall.SIGKILL
		// Memory access error
		case syscall.SIGBUS:
			sigToSend = syscall.SIGBUS
		// Invalid memory reference, probably access memory you dont own
		case syscall.SIGSEGV:
			sigToSend = syscall.SIGSEGV
		// Bad argument to a syscall or violated a seccomp rule
		case syscall.SIGSYS:
			sigToSend = syscall.SIGSYS
		// Attempted to write to pipe with a process on the other end
		case syscall.SIGPIPE:
			sigToSend = syscall.SIGPIPE
		// timer (real / clock time) set earlier has elapsed
		case syscall.SIGALRM:
			sigToSend = syscall.SIGALRM
		// Request termination similar to SIGINT
		case syscall.SIGTERM:
			sigToSend = syscall.SIGTERM
		// Socket has urgent / out of bound data to read
		case syscall.SIGURG:
			sigToSend = syscall.SIGURG
		// Stop a process for resuming later CTRL+Z
		case syscall.SIGSTOP:
			sigToSend = syscall.SIGSTOP
		//  Similar to SIGSTOP but cant be ignored
		case syscall.SIGTSTP:
			sigToSend = syscall.SIGTSTP
		// Resume after stopping
		case syscall.SIGCONT:
			sigToSend = syscall.SIGCONT
		// Child process has terminated, interupted or resumed
		case syscall.SIGCHLD:
			var status syscall.WaitStatus
			var rusage syscall.Rusage
			for {
				// kill our child's children
				retValue, _ := syscall.Wait4(-1, &status, syscall.WNOHANG, &rusage)
				if retValue <= 0 {
					break
				}
			}
			sigToSend = syscall.SIGCHLD
		// Attempted to read from TTY whilst in background
		case syscall.SIGTTIN:
			sigToSend = syscall.SIGTTIN
		// Arithmetic error such as divide by 0
		case syscall.SIGFPE:
			sigToSend = syscall.SIGFPE
		case syscall.SIGPROF:
			sigToSend = syscall.SIGPROF
		case syscall.SIGUSR1:
			sigToSend = syscall.SIGUSR1
		// User defined
		case syscall.SIGUSR2:
			sigToSend = syscall.SIGUSR2
		// CPU time used by timer elapsed
		case syscall.SIGVTALRM:
			sigToSend = syscall.SIGVTALRM
		// Terminal window size changed
		case syscall.SIGWINCH:
			sigToSend = syscall.SIGWINCH
		// Used up CPU duration previously set
		case syscall.SIGXCPU:
			sigToSend = syscall.SIGXCPU
		// File has grown too large
		case syscall.SIGXFSZ:
			sigToSend = syscall.SIGXFSZ
		}
		syscall.Kill(pid, sigToSend)
	}
}

func makeKey(k string, prefix string) string {
	k = strings.Replace(strings.Replace(k, "-", "_", -1), ".", "_", -1)
	k = strings.ToUpper(k)
	if prefix != "" && !strings.HasPrefix(k, prefix) {
		k = prefix + k
	}
	return k
}

func makeEnv(kv map[string]string) []string {
	env := make([]string, 0)
	c := make(map[string]string)
	// we first start off with the parents process env
	// which our child will inherit
	for _, s := range os.Environ() {
		tok := strings.Split(s, "=")
		c[tok[0]] = tok[1]
	}
	// we then merge in our incoming environment overwriting
	// any existing env values
	for k, v := range kv {
		c[k] = v
	}
	// now we create the new merged env
	for k, v := range c {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env
}

// dashCmd represents the dash command which will spawn a child process and manage
// monitoring config maps and secrets for changes and sending them down as environment
// variables
var dashCmd = &cobra.Command{
	Use:   "dash <secret_or_configmap, ...> -- <program> <args> <flags>",
	Short: "dash is a runner which monitors k8s object changes and manages child processes",
	Long: `The dash command will monitor one or more kubernetes objects (ConfigMaps and/or Secrets)
and will convert the values in the object data payload into environment variables
and in turn fork the command you support after the double dash with any arguments supplied.

The environment variables have a few simple formatting rules:

- Any dashes or periods are converted to underscore (e.g. foo-bar is foo_bar)
- All characters are uppercased (e.g. foo_bar is FOO_BAR)
- An optional prefix can be prepended if supplied with --prefix 
	(e.g. --prefix PP and foo-bar is PP_FOO_BAR)

The environment is first inherited from the parent process (this command) and any incoming
variables will take precedence.

Any parameters for configuring this command will need to proceed the double dash and any
parameters after the double dash are passed along to the forked process.

	pinpt dash c/foo=bar s/bar=foo -- mycommand foo --bar

The object names are expressed using a simple pattern: <type>/<key>=<value>
The <type> for ConfigMap is one of configmap, cm, m or c.
The <type> for Secret is one of secret, sec or s.
The <key>=<value> is a Kubernetes compatible object selector optionally separated by commas

For example, to find all Secrets matching the object labels app=my-cool-secret and 
vendor=pinpoint and all ConfigMaps matching the object labels component=agent, 
you would write:

	s/app=my-cool-secret,vendor=pinpoint m/component=agent

The result of both items are merged together into one environment.  If multiple objects have
the same variable, the behavior is undefined (meaning the order is not predictable).

All signals are sent to the forked process. However, dash will handle SIGINT, SIGTERM and SIGQUIT
by ensuring that the forked process is shutdown within 5 seconds or will force terminate the fork
and any children of the forked process.

To prevent config spam, the command will wait for a period of approximately 5 seconds of no changes
before restarting the forked process. This will prevent multiple changes from causing a constant
restart cycle.

The stdout, stderr and stdin pipes are all directly connected to the forked process.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		sep := cmd.ArgsLenAtDash()
		// make sure we have a command separator since it doesn't really work if we don't :)
		if sep < 0 || sep == len(args) {
			fmt.Println("missing command and optional arguments. here's some help:")
			fmt.Println()
			cmd.Help()
			os.Exit(1)
		}

		logger := NewLogger(cmd, "dash")

		monitorObjects := args[0:sep]
		command := args[sep : sep+1][0]
		commandArgs := args[sep+1:]
		namespace, _ := cmd.Flags().GetString("namespace")
		prefix, _ := cmd.Flags().GetString("prefix")

		Debug(logger, "starting", "cmd", command, "args", commandArgs, "monitor", monitorObjects, "namespace", namespace)

		var mu sync.Mutex
		config := make(map[string]string)
		configch := make(chan bool, 1)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		secretDir, _ := cmd.Flags().GetString("secretDir")
		if secretDir != "" && !FileExists(secretDir) {
			os.MkdirAll(secretDir, 0755)
		}

		if len(monitorObjects) > 0 {
			client, err := NewEnvClient()
			if err != nil {
				Fatal(logger, "error connecting to kubernetes", "err", err)
			}
			for _, object := range monitorObjects {
				tok := strings.Split(object, "/")
				if len(tok) != 2 {
					Fatal(logger, "expected object pattern: <type>/<key=value> such as cm:component=agent")
				}
				q := new(k.LabelSelector)
				sel := strings.Split(tok[1], ",")
				for _, s := range sel {
					t := strings.Split(strings.TrimSpace(s), "=")
					if len(t) == 1 {
						q.Eq("name", s)
					} else {
						q.Eq(t[0], t[1])
					}
				}
				switch tok[0] {
				case "configmap", "cm", "c", "m":
					{
						go func() {
							// keep trying to re-connect until our context is completed in case we have a disconnect
							// on the GRPC side
							for ctx.Err() == nil {
								Info(logger, "creating config watcher", "selector", q.Selector())
								watcher, err := client.CoreV1().WatchConfigMaps(ctx, namespace, q.Selector())
								if err != nil {
									Fatal(logger, "error creating config map watcher", "err", err, "selector", q.Selector())
								}
								defer watcher.Close()
								for {
									_, cm, err := watcher.Next()
									if err == io.EOF {
										break
									}
									if err == nil && cm != nil {
										mu.Lock()
										for k, v := range cm.Data {
											config[makeKey(k, prefix)] = v
										}
										mu.Unlock()
										configch <- true
									}
								}
							}
						}()
					}
				case "secret", "sec", "s":
					{
						go func() {
							// keep trying to re-connect until our context is completed in case we have a disconnect
							// on the GRPC side
							for ctx.Err() == nil {
								Info(logger, "creating secret watcher", "selector", q.Selector())
								watcher, err := client.CoreV1().WatchSecrets(ctx, namespace, q.Selector())
								if err != nil {
									Fatal(logger, "error creating secrets watcher", "err", err, "selector", q.Selector())
								}
								defer watcher.Close()
								for {
									_, sec, err := watcher.Next()
									if err == io.EOF {
										break
									}
									if err == nil && sec != nil {
										mu.Lock()
										for k, v := range sec.Data {
											envkey := makeKey(k, prefix)
											if secretDir != "" {
												// write out each secret into a file with the same name as the environment variable
												// so that you can optional read them from external programs like curl
												fn := filepath.Join(secretDir, envkey)
												ioutil.WriteFile(fn, v, 0400)
											}
											config[envkey] = string(v)
										}
										mu.Unlock()
										configch <- true
									}
								}
							}
						}()
					}
				default:
					{
						Fatal(logger, "unsupported object type", "object", object)
					}
				}
			}
		}

		var exitStatus int
		var configSHA string
		var lastConfig time.Time

		signalChannel2 := make(chan os.Signal, 2)
		signal.Notify(signalChannel2, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	Loop:
		for {
			exitch := make(chan int, 1)
			startch := make(chan bool, 1)
			signalChannel := make(chan os.Signal, 2)
			signal.Notify(signalChannel)
			var c *exec.Cmd
			var pendingChanges, pendingTerm bool
		Restart:
			for {
				select {
				case sig := <-signalChannel2:
					{
						// we need this channel in case we haven't started a child process yet
						// to be able to break out
						if c == nil {
							Debug(logger, "got a signal, no active command", "signal", sig)
							break Loop
						}
						Debug(logger, "got a signal", "signal", sig, "pid", c.Process.Pid)
					}
				case <-startch:
					{
						// when we get a start request, we launch the program
						Info(logger, "starting", "cmd", command, "args", Stringify(commandArgs))
						c = exec.Command(command, commandArgs...)
						c.Stdout = os.Stdout
						c.Stderr = os.Stderr
						c.Stdin = os.Stdin
						// we have to hold a lock since the watchers mutate this directly
						mu.Lock()
						c.Env = makeEnv(config)
						mu.Unlock()
						err := c.Start()
						if err != nil {
							Error(logger, "error running command", "cmd", command, "err", err)
							exitStatus = 255
							break Loop
						}
						Info(logger, "started", "cmd", command, "pid", c.Process.Pid)
						go sigHandler(c.Process.Pid, signalChannel)
						go func() {
							var exitCode int
							state, _ := c.Process.Wait()
							Info(logger, "exited", "cmd", command, "state", state, "pid", c.Process.Pid)
							if state != nil {
								if status, ok := state.Sys().(syscall.WaitStatus); ok {
									exitCode = status.ExitStatus()
								}
							}
							exitch <- exitCode
						}()
					}
				case ec := <-exitch:
					{
						exitStatus = ec
						Info(logger, "exit channel signaled", "pendingTerm", pendingTerm, "exitcode", exitStatus)
						signal.Stop(signalChannel)
						if !pendingTerm {
							break Loop
						}
						pendingTerm = false
						startch <- true
					}
				case <-configch:
					{
						Debug(logger, "config changed")
						mu.Lock()
						// we calculate a sha to compare against so
						// we don't restart in cases where the config
						// is the same
						newSHA := HashValues(config)
						if configSHA != newSHA {
							// set pending and when the 5s timer fires, we can
							// can compare the last change time and ensure that
							// we have a quiet period of no changes before we
							// restart ...
							pendingChanges = true
							lastConfig = time.Now()
							configSHA = newSHA
							for k, v := range config {
								Debug(logger, k+"="+v)
							}
						} else {
							Debug(logger, "config changed, but not any different than before")
						}
						mu.Unlock()
					}
				case <-time.After(5 * time.Second):
					{
						// check to see if we have pending changes and we haven't had any new
						// pending changes in >5s (quiet period)
						if pendingChanges && time.Since(lastConfig) >= time.Second*5 {
							Info(logger, "ready to make changes")
							pendingChanges = false
							if c != nil {
								pendingTerm = true
								Info(logger, "sending SIGTERM to child", "pid", c.Process.Pid)
								syscall.Kill(c.Process.Pid, syscall.SIGTERM)
								// on the next 5s iteration we'll check to see if the process exited
								// above and if not, we'll force kill it
							} else {
								startch <- true
							}
						} else if pendingTerm {
							if c != nil {
								Info(logger, "process didn't stop in 5s, sending a kill")
								c.Process.Kill()
							}
							// now we restart the process
							pendingTerm = false
							pendingChanges = false
							startch <- true
							break Restart
						}
					}
				}
			}
			Debug(logger, "restarting loop")
		}

		Info(logger, "exit", "code", exitStatus)
		os.Exit(exitStatus)
	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := dashCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func getEnvStringSlice(k string) []string {
	v := os.Getenv(k)
	if v == "" {
		return []string{}
	}
	return strings.Split(v, ",")
}

func init() {
	dashCmd.Flags().String("prefix", "", "the prefix to prepend to any environment name before sending")
	dashCmd.Flags().String("namespace", Getenv("PP_K8S_NAMESPACE", "default"), "kubernetes namespace to use")
	dashCmd.Flags().String("secretDir", "/var/run/dash", "directory to write secrets")
	dashCmd.Flags().String("log-level", Getenv("PP_LOG_LEVEL", "info"), "set the log level")
	dashCmd.Flags().String("log-color", "dark", "set the log color profile (dark or light). only applies to console logging")
	dashCmd.Flags().String("log-format", Getenv("PP_LOG_FORMAT", "default"), "set the log format (json, logfmt, default)")
	dashCmd.Flags().String("log-output", Getenv("PP_LOG_OUTPUT", "-"), "the location of the log file, use - for default or specify a location")
	dashCmd.Flags().StringSlice("log-ingestion", getEnvStringSlice("PP_LOG_INGESTION"), "one of more urls to log ingestion servers")
}
