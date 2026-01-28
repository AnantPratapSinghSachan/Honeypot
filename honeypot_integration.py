import csv
import json
import os
import threading
import time
import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, Optional

from ddqn_agent import HoneypotDDQNAgent, HoneypotState

#Attacker Tracker INFO
class AttackerProfile:
    
    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.request_count = 0
        self.failed_login_count = 0
        self.unique_paths = set()
        self.user_agents = set()
        self.ports_accessed = set()
        self.request_timestamps = deque(maxlen=100)
        self.payload_sizes = []
        self.attack_patterns = defaultdict(int)
        self.current_action = None
        self.action_history = []

    #Update attack_patterns
    def update(self, event_type: str, data: dict):    
        self.last_seen = time.time()
        self.request_count += 1
        self.request_timestamps.append(time.time())
        
        if event_type == 'http_request':
            self.unique_paths.add(data.get('path', ''))
            self.user_agents.add(data.get('user_agent', ''))
            
        elif event_type == 'login_attempt':
            self.failed_login_count += 1
            self.attack_patterns['brute_force'] += 1
            
        elif event_type == 'tcp_connect':
            self.ports_accessed.add(data.get('port', 0))
            if len(self.ports_accessed) > 5:
                self.attack_patterns['port_scan'] += 1
        
        self._detect_patterns(data)
    
    #Detect patterns
    def _detect_patterns(self, data: dict):
        path = data.get('path', '').lower()
        
        # SQL injection
        sql_keywords = ['union', 'select', 'drop', 'insert', '--', 'or 1=1']
        if any(kw in path for kw in sql_keywords):
            self.attack_patterns['sql_injection'] += 1
        
        # XSS
        xss_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=']
        if any(pat in path for pat in xss_patterns):
            self.attack_patterns['xss'] += 1
        
        # Path traversal
        if '../' in path or '..\\' in path:
            self.attack_patterns['path_traversal'] += 1
        
        #command injection
        cmd_patterns = ['|', ';', '`', '$(', '${']
        if any(pat in path for pat in cmd_patterns):
            self.attack_patterns['command_injection'] += 1
    
    #requests per minute
    def get_request_rate(self) -> float:
        if len(self.request_timestamps) < 2:
            return 0.0
        time_span = self.request_timestamps[-1] - self.request_timestamps[0]
        if time_span == 0:
            return 0.0
        return (len(self.request_timestamps) / time_span) * 60
    
    def is_brute_force(self) -> bool:
        """Detect brute force attack"""
        return self.failed_login_count > 5 or self.get_request_rate() > 30
    
    def get_session_duration(self) -> float:
        """Get total session duration in seconds"""
        return self.last_seen - self.first_seen
    
    def to_dict(self) -> dict:
        """Convert profile to dictionary for state extraction"""
        return {
            'request_rate': self.get_request_rate(),
            'unique_paths': len(self.unique_paths),
            'failed_logins': self.failed_login_count,
            'port_scans': len(self.ports_accessed),
            'payload_size_avg': np.mean(self.payload_sizes) if self.payload_sizes else 0,
            'is_known_attacker': 0,  # Could integrate with threat intel
            'suspicious_ua': len(self.user_agents) > 3,
            'session_duration': self.get_session_duration(),
            'sql_injection_attempts': self.attack_patterns['sql_injection'],
            'xss_attempts': self.attack_patterns['xss'],
            'path_traversal_attempts': self.attack_patterns['path_traversal'],
            'brute_force_detected': self.is_brute_force(),
            'credential_stuffing': self.failed_login_count > 10,
        }

#Monitor system state
class SystemMonitor:
    def __init__(self):
        self.active_connections = 0
        self.thread_count = 0
        self.cpu_usage = 0
        self.memory_usage = 0
        self.under_attack = False
        
        try:
            import psutil
            self.psutil = psutil
        except ImportError:
            self.psutil = None
    
    def update(self):
        """Update system metrics"""
        self.thread_count = threading.active_count()
        
        if self.psutil:
            try:
                self.cpu_usage = self.psutil.cpu_percent(interval=0.1)
                self.memory_usage = self.psutil.virtual_memory().percent
            except Exception:
                pass
    
    def to_dict(self) -> dict:
        """Convert to dictionary for state extraction"""
        return {
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'active_connections': self.active_connections,
            'thread_count': self.thread_count,
            'under_attack': self.under_attack,
        }


class TimeFeatures:
    """Extract temporal features"""
    
    @staticmethod
    def get_features() -> dict:
        now = datetime.now()
        return {
            'hour': now.hour,
            'day_of_week': now.weekday(),
            'is_weekend': now.weekday() >= 5,
            'time_since_last_attack': 0,  # Updated by HoneypotRL
        }

#Honeypot integration
class HoneypotRL:
    def __init__(self, agent_checkpoint: Optional[str] = None, log_dir: str = 'logs'):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Initialize DDQN agent
        self.agent = HoneypotDDQNAgent()
        if agent_checkpoint and os.path.exists(agent_checkpoint):
            self.agent.load_checkpoint(agent_checkpoint)
            print(f"Loaded agent from {agent_checkpoint}")
        
        # Tracking structures
        self.attacker_profiles: Dict[str, AttackerProfile] = {}
        self.system_monitor = SystemMonitor()
        self.last_attack_time = 0
        self.action_outcomes = deque(maxlen=1000)
        
        # Response handlers
        self.response_handlers = {
            0: self._handle_observe_silent,
            1: self._handle_engage_low,
            2: self._handle_engage_medium,
            3: self._handle_engage_high,
            4: self._handle_rate_limit,
            5: self._handle_temporary_block,
            6: self._handle_tarpit,
            7: self._handle_redirect_decoy,
            8: self._handle_alert_escalate,
        }
        
        # Blocked IPs and rate limits
        self.blocked_ips = {}  # ip -> unblock_time
        self.rate_limits = defaultdict(lambda: deque(maxlen=10))
        self.tarpit_ips = set()
        
        # Logging
        self.rl_log_file = os.path.join(log_dir, 'rl_decisions.csv')
        self._init_rl_log()
        
        # Training mode
        self.training_mode = True
        self.episode_reward = 0
        self.episode_length = 0

    #write to rl_log csv
    def _init_rl_log(self):
        if not os.path.exists(self.rl_log_file):
            with open(self.rl_log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'ip', 'action', 'action_name', 
                    'reward', 'request_rate', 'attack_type', 'outcome'
                ])
    
    def process_event(self, event_type: str, ip: str, data: dict) -> dict:
        # Check if IP is blocked
        if ip in self.blocked_ips:
            if time.time() < self.blocked_ips[ip]:
                return {'action': 'block', 'message': 'IP temporarily blocked'}
            else:
                del self.blocked_ips[ip]
        
        if ip not in self.attacker_profiles:
            self.attacker_profiles[ip] = AttackerProfile(ip
        profile = self.attacker_profiles[ip]
        profile.update(event_type, data)
        self.system_monitor.update()
        self.system_monitor.active_connections = len(self.attacker_profiles)
        state = self._get_state(profile)
        action = self.agent.select_action(state, eval_mode=not self.training_mode)
        
        
        #check if the profile is clean
        is_clean = not profile.attack_patterns
        is_first_request = profile.request_count == 1
        if is_first_request and is_clean:
            print(f"[DEMO FIX] IP {ip} is new and clean. Overriding agent's guess. Forcing action 0 (observe_silent).")
            action = 0 
        elif not is_clean:
             print(f"[DEMO INFO] IP {ip} is NOT clean. Attack patterns found: {list(profile.attack_patterns.keys())}")
        elif not is_first_request:
             print(f"[DEMO INFO] IP {ip} is on request #{profile.request_count}. Letting agent decide.")

        # Execute action and get response
        response = self.response_handlers[action](ip, profile, data)
        outcome = self._evaluate_outcome(action, profile, response)
        reward = self.agent.calculate_reward(action, outcome)
        
        if self.training_mode:
            next_state = self._get_state(profile)
            done = False
            self.agent.store_experience(state, action, reward, next_state, done)
            self.agent.train_step()
            self.episode_reward += reward
            self.episode_length += 1
            
        #logging decisions
        self._log_decision(ip, action, reward, profile, outcome)
        
        #update action history
        profile.current_action = action
        profile.action_history.append((time.time(), action))    
        return response
    
    def _get_state(self, profile: AttackerProfile) -> np.ndarray:
        time_features = TimeFeatures.get_features()
        time_features['time_since_last_attack'] = time.time() - self.last_attack_time
        
        return HoneypotState.extract_features(
            attacker_profile=profile.to_dict(),
            system_state=self.system_monitor.to_dict(),
            time_features=time_features
        )
    
    def _evaluate_outcome(self, action: int, profile: AttackerProfile, response: dict) -> dict:
        outcome = {
            'data_collected': 0.0,
            'attacker_time_wasted': 0.0,
            'system_load': self.system_monitor.cpu_usage / 100.0,
            'detection_evasion': 0.0,
            'attack_prevented': 0.0,
            'threat_intelligence': 0.0,
            'resource_waste': 0.0,
            'stealth_maintained': 0.0,
            'deception_successful': 0.0,
            'redirected_successfully': 0.0,
        }
        
        outcome['data_collected'] = min(1.0, profile.request_count / 20)
        outcome['threat_intelligence'] = len(profile.attack_patterns) / 5
        session_minutes = profile.get_session_duration() / 60
        outcome['attacker_time_wasted'] = min(1.0, session_minutes / 30)
        
        #request rate = better stealth
        if profile.get_request_rate() < 10:
            outcome['stealth_maintained'] = 1.0
        
        #deception success
        if action in [2, 3] and profile.request_count > 5:
            outcome['deception_successful'] = 1.0
        
        #attack prevented
        if action in [4, 5, 6] and profile.is_brute_force():
            outcome['attack_prevented'] = 1.0
        if self.system_monitor.cpu_usage > 80:
            outcome['resource_waste'] = 1.0
        
        return outcome
    
    #RESPONSE HANDLING
    def _handle_observe_silent(self, ip: str, profile: AttackerProfile, data: dict) -> dict:
        return {
            'action': 'observe',
            'response_type': 'minimal',
            'delay': 0,
            'message': None
        }
    
    def _handle_engage_low(self, ip: str, profile: AttackerProfile, data: dict) -> dict:
        return {
            'action': 'engage_low',
            'response_type': 'standard',
            'delay': 0.1,
            'serve_fake_data': False,
            'message': 'Standard response'
        }
    
    def _handle_engage_medium(self, ip: str, profile: AttackerProfile, data: dict) -> dict:
        return {
            'action': 'engage_medium',
            'response_type': 'deceptive',
            'delay': 0.5,
            'serve_fake_data': True,
            'fake_data_type': 'credentials',
            'message': 'Serving fake data'
        }
    
    def _handle_engage_high(self, ip: str, profile: AttackerProfile, data: dict) -> dict:
        return {
            'action': 'engage_high',
            'response_type': 'advanced_deception',
            'delay': 1.0,
            'serve_fake_data': True,
            'fake_data_type': 'database_dump',
            'interactive_shell': True,
            'message': 'Advanced deception active'
        }
    
    def _handle_rate_limit(self, ip: str, profile: AttackerProfile, data: dict) -> dict:
        self.rate_limits[ip].append(time.time())
        
        return {
            'action': 'rate_limit',
            'response_type': 'delayed',
            'delay': 2.0,
            'max_requests_per_minute': 10,
            'message': 'Rate limit applied'
        }
    
    def _handle_temporary_block(self, ip: str, profile: AttackerProfile, data: dict) -> dict:
        block_duration = 300  
        self.blocked_ips[ip] = time.time() + block_duration
        
        return {
            'action': 'block',
            'response_type': 'blocked',
            'block_duration': block_duration,
            'message': f'IP blocked for {block_duration}s'
        }
    
    def _handle_tarpit(self, ip: str, profile: AttackerProfile, data: dict) -> dict:
        """Slow down attacker (tarpit)"""
        self.tarpit_ips.add(ip)
        
        return {
            'action': 'tarpit',
            'response_type': 'slow',
            'delay': 10.0,
            'bandwidth_limit': 1024,
            'message': 'Tarpit activated'
        }
    
    def _handle_redirect_decoy(self, ip: str, profile: AttackerProfile, data: dict) -> dict:
        return {
            'action': 'redirect',
            'response_type': 'redirect',
            'target': 'high_interaction_honeypot',
            'preserve_state': True,
            'message': 'Redirected to decoy'
        }
    
    def _handle_alert_escalate(self, ip: str, profile: AttackerProfile, data: dict) -> dict:
        alert_data = {
            'ip': ip,
            'threat_level': 'high',
            'attack_patterns': dict(profile.attack_patterns),
            'request_count': profile.request_count,
            'session_duration': profile.get_session_duration(),
        }
        print(f"[ALERT] Escalating threat from {ip}: {alert_data}")
        
        return {
            'action': 'alert',
            'response_type': 'escalated',
            'alert_data': alert_data,
            'message': 'Threat escalated'
        }
    
    def _log_decision(self, ip: str, action: int, reward: float, 
                     profile: AttackerProfile, outcome: dict):
        """Log RL decision for analysis"""
        with open(self.rl_log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now(timezone.utc).isoformat(),
                ip,
                action,
                self.agent.get_action_name(action),
                f"{reward:.2f}",
                f"{profile.get_request_rate():.2f}",
                ','.join(profile.attack_patterns.keys()),
                json.dumps(outcome)
            ])
    
    def save_agent(self, filepath: str):
        """Save trained agent"""
        self.agent.save_checkpoint(filepath)
    
    def load_agent(self, filepath: str):
        """Load trained agent"""
        self.agent.load_checkpoint(filepath)
    
    def set_training_mode(self, enabled: bool):
        """Enable or disable training mode"""
        self.training_mode = enabled
        print(f"Training mode: {'enabled' if enabled else 'disabled'}")
    
    def get_statistics(self) -> dict:
        """Get current statistics"""
        return {
            'active_attackers': len(self.attacker_profiles),
            'blocked_ips': len(self.blocked_ips),
            'tarpit_ips': len(self.tarpit_ips),
            'episode_reward': self.episode_reward,
            'episode_length': self.episode_length,
            'agent_epsilon': self.agent.epsilon,
            'memory_size': len(self.agent.memory),
        }


def integrate_with_honeypot():
    rl_honeypot = HoneypotRL(agent_checkpoint='checkpoints/agent_latest.pt')
    event = {
        'type': 'http_request',
        'ip': '192.168.1.100',
        'data': {
            'method': 'POST',
            'path': '/login?id=1 OR 1=1',
            'user_agent': 'Mozilla/5.0 (Scanner)'
        }
    }
    
    response = rl_honeypot.process_event(
        event['type'],
        event['ip'],
        event['data']
    )
    
    print(f"RL Agent Decision: {response}")
    if rl_honeypot.episode_length % 1000 == 0:
        rl_honeypot.save_agent('checkpoints/agent_latest.pt')
    
    return response


if __name__ == "__main__":
    print("Honeypot RL Integration Module")
    print("=" * 50)
    integrate_with_honeypot()
