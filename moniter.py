#!/usr/bin/env python3

import time
import os
import csv
from datetime import datetime
from collections import Counter, deque
import pandas as pd

def format_row(row: dict) -> str:
    ts = row.get('timestamp', '')
    ip = row.get('ip', '')
    action = row.get('action_name', row.get('action', ''))
    reward = row.get('reward', '')
    attack = row.get('attack_type', '')
    return f"{ts} | {ip:>15} | {action:<18} | reward={reward:>5} | {attack}"

def monitor():
    rl_log = 'logs/rl_decisions.csv'

    print("="*60)
    print("RL Honeypot Monitor - Press Ctrl+C to stop")
    print("="*60)

    last_pos = 0
    buffer_incomplete = ''
    printed_header = False
    stats_window = deque(maxlen=200)

    try:
        while True:
            try:
                if not os.path.exists(rl_log):
                    if not printed_header:
                        print("Waiting for logs at logs/rl_decisions.csv ...")
                        printed_header = True
                    time.sleep(2)
                    continue
                    
                size = os.path.getsize(rl_log)
                if last_pos > size:
                    last_pos = 0
                    
                with open(rl_log, 'r', encoding='utf-8', newline='') as f:
                    f.seek(last_pos)
                    chunk = f.read()
                    last_pos = f.tell()

                if not chunk:
                    time.sleep(2)
                    continue

                chunk = buffer_incomplete + chunk
                lines = chunk.splitlines(True)
                complete_lines = [ln for ln in lines if ln.endswith('\n') or ln.endswith('\r')]
                buffer_incomplete = '' if len(complete_lines) == len(lines) else lines[-1]

                new_rows = []
                reader = csv.reader(line for line in ''.join(complete_lines).splitlines())
                for row in reader:
                    if not row:
                        continue
                    if row[0].lower().startswith('timestamp'):
                        continue
                    try:
                        d = {
                            'timestamp': row[0],
                            'ip': row[1],
                            'action': row[2],
                            'action_name': row[3],
                            'reward': row[4],
                            'request_rate': row[5],
                            'attack_type': row[6],
                            'outcome': row[7] if len(row) > 7 else ''
                        }
                    except Exception:
                        keys = ['timestamp','ip','action','action_name','reward','request_rate','attack_type','outcome']
                        d = dict(zip(keys, row + ['']*(len(keys)-len(row))))
                    new_rows.append(d)

                if new_rows:
                    now = datetime.now().strftime('%H:%M:%S')
                    print(f"\n[{now}] Recent Activity (last {len(new_rows)} entries):")
                    for d in new_rows[-10:]:
                        print('  ' + format_row(d))
                        stats_window.append(d)

                    if pd is not None:
                        try:
                            df = pd.DataFrame(list(stats_window))
                            print(f"\nTotal (window): {len(df)} | Unique IPs: {df['ip'].nunique()}")
                            print(f"Avg Reward (window): {pd.to_numeric(df['reward'], errors='coerce').mean():.2f}")
                            print("Action Distribution (window):")
                            print(df['action_name'].value_counts().head().to_string())
                        except Exception:
                            pass
                    else:
                        actions = Counter(d['action_name'] for d in stats_window)
                        uniq_ips = len({d['ip'] for d in stats_window})
                        try:
                            rewards = [float(d['reward']) for d in stats_window if d['reward'] not in (None, '')]
                            avg_reward = sum(rewards)/len(rewards) if rewards else 0.0
                        except Exception:
                            avg_reward = 0.0
                        print(f"\nTotal (window): {len(stats_window)} | Unique IPs: {uniq_ips}")
                        print(f"Avg Reward (window): {avg_reward:.2f}")
                        print("Action Distribution (window):")
                        for name, cnt in actions.most_common(5):
                            print(f"  {name}: {cnt}")

                time.sleep(2)

            except KeyboardInterrupt:
                print("\nMonitor stopped")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(2)
    except KeyboardInterrupt:
        print("\nMonitor stopped")

if __name__ == "__main__":
    monitor()

