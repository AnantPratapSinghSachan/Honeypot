#!/usr/bin/env python3
import sys
import threading
import time
from honeypot_integration import HoneypotRL
from honeypot import (
    run_http_server, tcp_listener, run_icmp_sniffer, 
    system_monitor, TCP_PORTS, HTTP_PORT
)

def main():
    print("[RL] Initializing DDQN agent...")
    rl_honeypot = HoneypotRL(
        agent_checkpoint='checkpoints/agent_final.pt',
        log_dir='logs'
    )
    
    rl_honeypot.set_training_mode(False)
    print("[RL] Agent loaded in evaluation mode")
    
    import honeypot
    honeypot.rl_honeypot = rl_honeypot
    
    stop_evt = threading.Event()
    
    mon_thr = threading.Thread(
        target=system_monitor, 
        args=(stop_evt,), 
        name="monitor", 
        daemon=True
    )
    mon_thr.start()

    #https listeners
    http_thr = threading.Thread(
        target=run_http_server, 
        name="http", 
        daemon=True
    )
    http_thr.start()
    
    #TCP listeners
    tcp_threads = []
    for p in TCP_PORTS:
        thr = threading.Thread(
            target=tcp_listener, 
            args=(p, stop_evt), 
            name=f"tcp-{p}", 
            daemon=True
        )
        thr.start()
        tcp_threads.append(thr)
    
    #Start ICMP sniffer
    icmp_thr = threading.Thread(
        target=run_icmp_sniffer, 
        name="icmp", 
        daemon=True
    )
    icmp_thr.start()
    
    print("\n" + "="*60)
    print("[Start] RL-Enhanced Honeypot Running")
    print("="*60)
    print(f"HTTP Server: port {HTTP_PORT}")
    print(f"TCP Listeners: {TCP_PORTS}")
    print(f"DDQN Agent: ACTIVE (evaluation mode)")
    print(f"Logs: logs/")
    print("="*60 + "\n")
    
    try:
        while True:
            time.sleep(10)
            stats = rl_honeypot.get_statistics()
            if stats['active_attackers'] > 0:
                print(f"[Stats] Attackers: {stats['active_attackers']}, "
                      f"Blocked: {stats['blocked_ips']}, "
                      f"Epsilon: {stats['agent_epsilon']:.4f}")
    except KeyboardInterrupt:
        print("\n[RL] Stopping honeypot...")
        stop_evt.set()
        print("\n" + "="*60)
        print("Final Statistics:")
        stats = rl_honeypot.get_statistics()
        for key, value in stats.items():
            print(f"  {key}: {value}")
        print("="*60)

if __name__ == "__main__":

    main()
