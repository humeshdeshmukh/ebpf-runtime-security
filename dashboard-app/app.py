import os
import json
import subprocess
from flask import Flask, jsonify, send_from_directory

app = Flask(__name__, static_folder='static')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_DIR = os.path.join(BASE_DIR, 'dashboards')
TELEMETRY_DIR = os.path.join(BASE_DIR, 'hubble-telemetry')

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(app.static_folder, path)

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip(), True
        return result.stderr.strip(), False
    except Exception as e:
        return str(e), False

def get_k8s_status():
    _, minikube_ok = run_cmd("minikube status")
    _, kubectl_ok = run_cmd("kubectl get nodes")
    
    tetragon_ok = False
    hubble_ok = False
    
    if kubectl_ok:
        pods_str, _ = run_cmd("kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon --no-headers")
        tetragon_ok = "Running" in pods_str if pods_str else False
        
        hubble_str, _ = run_cmd("kubectl get pods -n kube-system -l app.kubernetes.io/name=hubble --no-headers")
        hubble_ok = "Running" in hubble_str if hubble_str else False
        if not hubble_ok:
            # Also check if cilium has hubble enabled
            cilium_pods, _ = run_cmd("kubectl get pods -n kube-system -l k8s-app=cilium --no-headers")
            hubble_ok = "Running" in cilium_pods if cilium_pods else False

    return {
        "minikube": "Running" if minikube_ok else "Stopped",
        "kubernetes": "Available" if kubectl_ok else "Unavailable",
        "tetragon": "Active" if tetragon_ok else "Inactive",
        "hubble": "Active" if hubble_ok else "Inactive"
    }

def parse_tetragon_line(raw_line):
    try:
        evt = json.loads(raw_line)
        timestamp = evt.get("time", "")
        
        # Process Exec
        if "process_exec" in evt:
            p_exec = evt["process_exec"]
            proc = p_exec.get("process", {})
            binary = proc.get("binary", "")
            args = proc.get("arguments", "")
            pod = proc.get("pod", {}).get("name", "host")
            ns = proc.get("pod", {}).get("namespace", "")
            return {
                "timestamp": timestamp,
                "event_type": "process_exec",
                "process": binary,
                "arguments": args,
                "pod": pod,
                "namespace": ns,
                "status": "Allowed",
                "policy": "none",
                "details": f"Process '{binary} {args}' executed inside pod '{pod}'."
            }
        
        # Process Exit
        if "process_exit" in evt:
            p_exit = evt["process_exit"]
            proc = p_exit.get("process", {})
            binary = proc.get("binary", "")
            pod = proc.get("pod", {}).get("name", "host")
            ns = proc.get("pod", {}).get("namespace", "")
            code = p_exit.get("status", 0)
            status = "Terminated (SIGKILL)" if code == 137 else f"Exited ({code})"
            return {
                "timestamp": timestamp,
                "event_type": "process_exit",
                "process": binary,
                "arguments": "",
                "pod": pod,
                "namespace": ns,
                "status": status,
                "policy": "none",
                "details": f"Process '{binary}' in pod '{pod}' exited with code {code}."
            }

        # Kprobes
        if "process_kprobe" in evt:
            pk = evt["process_kprobe"]
            proc = pk.get("process", {})
            binary = proc.get("binary", "")
            args = proc.get("arguments", "")
            pod = proc.get("pod", {}).get("name", "host")
            ns = proc.get("pod", {}).get("namespace", "")
            action = pk.get("action", "")
            func = pk.get("function_name", "")
            policy = pk.get("policy_name", "unknown")
            
            status = "Allowed"
            if "SIGKILL" in action or action == "KPROBE_ACTION_SIGKILL":
                status = "Blocked (SIGKILL)"
                
            return {
                "timestamp": timestamp,
                "event_type": f"kprobe_{func}",
                "process": binary,
                "arguments": args,
                "pod": pod,
                "namespace": ns,
                "status": status,
                "policy": policy,
                "details": f"TracingPolicy '{policy}' triggered on function '{func}'. Action: {status}."
            }
    except Exception:
        pass
    return None

def clean_pod_name(pod):
    if not pod:
        return "host"
    if pod.startswith("payment-gateway"):
        return "payment-gateway"
    if pod.startswith("compromised-pod"):
        return "compromised-pod"
    if pod.startswith("coredns") or pod.startswith("kube-dns"):
        return "kube-dns"
    if pod.startswith("tetragon"):
        return "tetragon"
    parts = pod.split('-')
    if len(parts) > 2:
        if len(parts[-1]) == 5 and len(parts[-2]) in (8, 9, 10):
            return "-".join(parts[:-2])
        return "-".join(parts[:-1])
    return pod

def parse_hubble_line(raw_line):
    try:
        flow = json.loads(raw_line)
        if "flow" in flow:
            flow = flow["flow"]
        time = flow.get("time", "")
        verdict = flow.get("verdict", "FORWARDED")
        
        src_pod = flow.get("source", {}).get("pod_name", "host")
        dst_pod = flow.get("destination", {}).get("pod_name", "")
        
        if not dst_pod:
            labels = flow.get("destination", {}).get("labels", [])
            dst_pod = "external"
            for label in labels:
                if "k8s-app=kube-dns" in label:
                    dst_pod = "kube-dns"
                    break
                elif "stripe" in label:
                    dst_pod = "api.stripe.com"
                    break
                elif "google" in label:
                    dst_pod = "google.com"
                    break
        
        dst_port = 0
        proto = "TCP"
        if "l4" in flow:
            l4 = flow["l4"]
            if "TCP" in l4:
                dst_port = l4["TCP"].get("destination_port", 0)
                proto = "TCP"
            elif "UDP" in l4:
                dst_port = l4["UDP"].get("destination_port", 0)
                proto = "UDP"
                
        if dst_port == 53:
            dst_pod = "kube-dns"
            
        src_clean = clean_pod_name(src_pod)
        dst_clean = clean_pod_name(dst_pod)
            
        return {
            "timestamp": time,
            "source": src_clean,
            "destination": dst_clean,
            "destination_port": dst_port,
            "protocol": proto,
            "verdict": verdict,
            "details": f"Traffic {verdict.lower()} to {dst_clean}:{dst_port} ({proto})"
        }
    except Exception:
        pass
    return None

@app.route('/api/status')
def status():
    return jsonify(get_k8s_status())

@app.route('/api/telemetry')
def telemetry():
    status_info = get_k8s_status()
    use_simulation = status_info["kubernetes"] == "Unavailable" or status_info["tetragon"] == "Inactive"

    events = []
    flows = []

    if not use_simulation:
        # Read real Tetragon events
        cmd = "kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout --tail=150"
        logs_str, ok = run_cmd(cmd)
        if ok and logs_str:
            for line in logs_str.split('\n'):
                if line.strip():
                    parsed = parse_tetragon_line(line)
                    if parsed:
                        events.append(parsed)
        # Reverse to show newest first
        events.reverse()

        # Read real Hubble flows
        # First get Cilium pod name to query Hubble via kubectl exec
        cmd_get_cilium = "kubectl get pods -n kube-system -l k8s-app=cilium -o jsonpath='{.items[0].metadata.name}'"
        cilium_pod, cilium_ok = run_cmd(cmd_get_cilium)
        hubble_str = ""
        ok = False
        if cilium_ok and cilium_pod:
            cmd_hubble = f"kubectl exec -n kube-system {cilium_pod} -c cilium-agent -- hubble observe --last 200 -o json"
            hubble_str, ok = run_cmd(cmd_hubble)
        
        if not ok or not hubble_str:
            cmd_hubble = "hubble observe --last 200 -o json"
            hubble_str, ok = run_cmd(cmd_hubble)
            if not ok or not hubble_str:
                cmd_hubble = "minikube ssh 'hubble observe --last 200 -o json'"
                hubble_str, ok = run_cmd(cmd_hubble)
            
        if ok and hubble_str:
            for line in hubble_str.split('\n'):
                if line.strip():
                    parsed = parse_hubble_line(line)
                    if parsed:
                        flows.append(parsed)
        flows.reverse()

    # Fallback to simulated files if lists are empty or offline
    if not events:
        try:
            with open(os.path.join(DASHBOARD_DIR, 'security_audit.json'), 'r') as f:
                for line in f:
                    if line.strip():
                        parsed = parse_tetragon_line(line)
                        if parsed:
                            events.append(parsed)
            # Reverse fallback events so newest are first
            events.reverse()
        except Exception:
            events = []

    if not flows:
        try:
            with open(os.path.join(DASHBOARD_DIR, 'network_flows.json'), 'r') as f:
                for line in f:
                    if line.strip():
                        parsed = parse_hubble_line(line)
                        if parsed:
                            flows.append(parsed)
            flows.reverse()
        except Exception:
            flows = []

    return jsonify({
        "mode": "Simulated (Cluster Offline)" if use_simulation else "Real-time (eBPF Kernel Probes)",
        "security_events": events,
        "network_flows": flows
    })

@app.route('/api/topology')
def topology():
    try:
        with open(os.path.join(TELEMETRY_DIR, 'network_map.json'), 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e), "nodes": [], "links": []})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
