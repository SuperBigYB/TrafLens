package main

// This lab-only client uses the upstream public UDP/gob debug protocol.
// Its fixed commands read receiver/L7/platform status or set WARN for those
// logging modules; it cannot alter controller configuration or database data.
import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

type DebugMessage struct {
	Module, Operate uint16
	Result          uint32
	Args            []byte
}

func command(module, operate uint16, args []byte) (string, error) {
	conn, err := net.Dial("udp", "[::1]:39527")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var request bytes.Buffer
	err = gob.NewEncoder(&request).Encode(DebugMessage{Module: module, Operate: operate, Args: args})
	if err != nil {
		return "", err
	}
	if _, err = conn.Write(request.Bytes()); err != nil {
		return "", err
	}
	var output bytes.Buffer
	for {
		packet := make([]byte, 9710)
		n, err := conn.Read(packet)
		if err != nil {
			return "", err
		}
		var response DebugMessage
		if err = gob.NewDecoder(bytes.NewReader(packet[:n])).Decode(&response); err != nil {
			return "", err
		}
		if response.Result != 0 {
			return "", fmt.Errorf("debug server result %d", response.Result)
		}
		output.Write(response.Args)
		if len(response.Args) < 9582 {
			return output.String(), nil
		}
	}
}

func main() {
	output := map[string]string{}
	if len(os.Args) == 2 && os.Args[1] == "warn" {
		for _, module := range []string{"receiver", "flow_log", "flow_log.decoder", "flow_log.dbwriter", "flow_log.log_data", "ext_metrics.decoder", "ext_metrics.dbwriter", "ckwriter", "statsd"} {
			var payload bytes.Buffer
			gob.NewEncoder(&payload).Encode(module + "|WARNING")
			result, err := command(20, 1, payload.Bytes())
			if err != nil {
				output[module] = "ERROR: " + err.Error()
			} else {
				var level string
				gob.NewDecoder(bytes.NewBufferString(result)).Decode(&level)
				output[module] = level
			}
		}
	} else if len(os.Args) == 1 {
		for _, query := range []struct {
			Name            string
			Module, Operate uint16
		}{
			{"receiver_metrics", 40, 3},
			{"receiver_l4_flow", 40, 4},
			{"receiver_l7_log", 40, 5},
			{"receiver_agent_stats", 40, 10},
			{"l7_decoder", 38, 0},
			{"flowlog_platform", 34, 0},
		} {
			result, err := command(query.Module, query.Operate, nil)
			if err != nil {
				result = "ERROR: " + err.Error()
			}
			output[query.Name] = result
		}
	} else {
		fmt.Fprintln(os.Stderr, "usage: backend-probe [warn]")
		os.Exit(2)
	}
	json.NewEncoder(os.Stdout).Encode(output)
}
