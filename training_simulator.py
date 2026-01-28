#!/usr/bin/env python3
import numpy as np
import random
import json
import os
from typing import List, Tuple, Dict
from datetime import datetime
import matplotlib.pyplot as plt

from ddqn_agent import HoneypotDDQNAgent, HoneypotState


class AttackScenario:
    
    SCENARIOS = {
        'reconnaissance': {
            'request_rate': (5, 20),
            'unique_paths': (10, 50),
            'failed_logins': (0, 2),
            'port_scans': (10, 100),
            'duration': (300, 1800),
            'detection_risk': 0.3,
        },
        'brute_force': {
            'request_rate': (50, 200),
            'unique_paths': (1, 5),
            'failed_logins': (10, 100),
            'port_scans': (0, 5),
            'duration': (60, 600),
            'detection_risk': 0.7,
        },
        'sql_injection': {
            'request_rate': (10, 40),
            'unique_paths': (5, 30),
            'failed_logins': (0, 5),
            'port_scans': (0, 10),
            'duration': (120, 900),
            'detection_risk': 0.5,
        },
        'ddos': {
            'request_rate': (200, 1000),
            'unique_paths': (1, 10),
            'failed_logins': (0, 10),
            'port_scans': (0, 20),
            'duration': (30, 300),
            'detection_risk': 0.9,
        },
        'stealth_exfiltration': {
            'request_rate': (1, 10),
            'unique_paths': (5, 20),
            'failed_logins': (0, 2),
            'port_scans': (5, 30),
            'duration': (1800, 7200),
            'detection_risk': 0.2,
        },
        'automated_scanner': {
            'request_rate': (30, 100),
            'unique_paths': (50, 200),
            'failed_logins': (5, 20),
            'port_scans': (50, 200),
            'duration': (180, 900),
            'detection_risk': 0.6,
        },
    }
    
    def __init__(self, scenario_type: str):
        self.type = scenario_type
        self.config = self.SCENARIOS[scenario_type]
        self.step_count = 0
        self.detected = False
        
    def generate_state(self) -> dict:
        attacker_profile = {
            'request_rate': random.uniform(*self.config['request_rate']),
            'unique_paths': random.randint(*self.config['unique_paths']),
            'failed_logins': random.randint(*self.config['failed_logins']),
            'port_scans': random.randint(*self.config['port_scans']),
            'payload_size_avg': random.uniform(100, 5000),
            'is_known_attacker': random.choice([0, 1]) if random.random() < 0.1 else 0,
            'suspicious_ua': random.choice([0, 1]) if random.random() < 0.3 else 0,
            'session_duration': random.uniform(*self.config['duration']),
        }
        
        attacker_profile['sql_injection_attempts'] = 0
        attacker_profile['xss_attempts'] = 0
        attacker_profile['path_traversal_attempts'] = 0
        attacker_profile['brute_force_detected'] = 0
        attacker_profile['credential_stuffing'] = 0
        
        if self.type == 'sql_injection':
            attacker_profile['sql_injection_attempts'] = random.randint(5, 50)
            attacker_profile['xss_attempts'] = random.randint(0, 5)
            attacker_profile['path_traversal_attempts'] = random.randint(0, 5)
        elif self.type == 'brute_force':
            attacker_profile['brute_force_detected'] = 1
            attacker_profile['credential_stuffing'] = random.choice([0, 1])
        elif self.type == 'automated_scanner':
            attacker_profile['sql_injection_attempts'] = random.randint(1, 10)
            attacker_profile['xss_attempts'] = random.randint(1, 10)
            attacker_profile['path_traversal_attempts'] = random.randint(1, 10)
        
        system_state = {
            'cpu_usage': min(100, 20 + attacker_profile['request_rate'] / 10),
            'memory_usage': random.uniform(30, 80),
            'active_connections': random.randint(1, 50),
            'thread_count': random.randint(10, 300),
            'under_attack': 1 if attacker_profile['request_rate'] > 100 else 0,
        }
        
        time_features = {
            'hour': random.randint(0, 23),
            'day_of_week': random.randint(0, 6),
            'is_weekend': random.choice([0, 1]),
            'time_since_last_attack': random.uniform(0, 3600),
        }
        
        return {
            'attacker_profile': attacker_profile,
            'system_state': system_state,
            'time_features': time_features,
        }
    
    def calculate_outcome(self, action: int, state_data: dict) -> dict:
        """Calculate realistic outcome based on action and scenario"""
        outcome = {
            'data_collected': 0.0,
            'attacker_time_wasted': 0.0,
            'system_load': 0.0,
            'detection_evasion': 0.0,
            'attack_prevented': 0.0,
            'threat_intelligence': 0.0,
            'resource_waste': 0.0,
            'stealth_maintained': 0.0,
            'deception_successful': 0.0,
            'redirected_successfully': 0.0,
        }
        
        attacker = state_data['attacker_profile']
        system = state_data['system_state']
        
        outcome['system_load'] = system['cpu_usage'] / 100.0
        
        if action == 0:  # observe_silent
            outcome['data_collected'] = 0.3
            outcome['stealth_maintained'] = 0.9
            outcome['attacker_time_wasted'] = 0.1
            
        elif action == 1:  # engage_low
            outcome['data_collected'] = 0.5
            outcome['attacker_time_wasted'] = 0.3
            outcome['stealth_maintained'] = 0.7
            if random.random() < 0.2:
                outcome['detection_evasion'] = 1.0
                
        elif action == 2:  # engage_medium
            outcome['data_collected'] = 0.8
            outcome['attacker_time_wasted'] = 0.6
            outcome['deception_successful'] = 0.6
            outcome['threat_intelligence'] = 0.7
            if random.random() < 0.3:
                outcome['detection_evasion'] = 1.0
                
        elif action == 3:  # engage_high
            outcome['data_collected'] = 1.0
            outcome['attacker_time_wasted'] = 0.9
            outcome['deception_successful'] = 0.8
            outcome['threat_intelligence'] = 1.0
            outcome['system_load'] += 0.2
            if random.random() < 0.4:
                outcome['detection_evasion'] = 1.0
                
        elif action == 4:  # rate_limit
            if attacker['request_rate'] > 50:
                outcome['attack_prevented'] = 0.7
                outcome['attacker_time_wasted'] = 0.5
            outcome['data_collected'] = 0.4
            
        elif action == 5:  # temporary_block
            if attacker.get('brute_force_detected', 0) or attacker['request_rate'] > 100:
                outcome['attack_prevented'] = 1.0
                outcome['attacker_time_wasted'] = 0.8
            else:
                outcome['resource_waste'] = 0.5
            outcome['data_collected'] = 0.2
            
        elif action == 6:  # tarpit
            outcome['attacker_time_wasted'] = 1.0
            outcome['attack_prevented'] = 0.8
            outcome['system_load'] += 0.3
            outcome['data_collected'] = 0.6
            
        elif action == 7:  # redirect_decoy
            outcome['redirected_successfully'] = 0.85
            outcome['data_collected'] = 0.9
            outcome['threat_intelligence'] = 0.9
            outcome['attacker_time_wasted'] = 0.7
            
        elif action == 8:  # alert_escalate
            outcome['attack_prevented'] = 0.6
            outcome['threat_intelligence'] = 0.5
            if attacker['request_rate'] < 30:
                outcome['resource_waste'] = 0.4  # False alarm
        
        if self.type == 'reconnaissance':
            if action in [0, 1]:  # Observing
                outcome['data_collected'] *= 1.5
                outcome['threat_intelligence'] *= 1.3
                
        elif self.type == 'brute_force':
            if action in [4, 5, 6]:  # Blocking
                outcome['attack_prevented'] *= 1.5
            if action in [2, 3]:  # DONT ENGAGE
                outcome['detection_evasion'] *= 1.5
                
        elif self.type == 'stealth_exfiltration':
            if action == 0:  # Silent observation
                outcome['data_collected'] *= 1.8
                outcome['stealth_maintained'] = 1.0
            elif action in [5, 8]:  # Blocking alerts
                outcome['detection_evasion'] = 1.0
                
        elif self.type == 'ddos':
            if action in [5, 6]:  #block DDoS
                outcome['attack_prevented'] = 1.0
                outcome['system_load'] *= 0.5  # Reduces load
            else:
                outcome['system_load'] *= 2.0  # System overload
                outcome['resource_waste'] = 1.0
        
        if outcome['detection_evasion'] > 0:
            self.detected = True
        
        return outcome
    
    def is_terminal(self) -> bool:
        """Check if episode should terminate"""
        self.step_count += 1
        
        if self.detected and random.random() < 0.7:
            return True

        if self.step_count > 50:
            return True

        if random.random() < 0.02:
            return True
            
        return False


class HoneypotSimulator:
    
    def __init__(self):
        self.current_scenario = None
        self.episode_count = 0
        
    def reset(self) -> Tuple[np.ndarray, str]:
        """Reset environment and return initial state"""
        scenario_type = random.choice(list(AttackScenario.SCENARIOS.keys()))
        self.current_scenario = AttackScenario(scenario_type)
        
        state_data = self.current_scenario.generate_state()
        state_vector = HoneypotState.extract_features(
            state_data['attacker_profile'],
            state_data['system_state'],
            state_data['time_features']
        )
        
        self.episode_count += 1
        return state_vector, scenario_type
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, dict]:
        """
        Execute action and return next state, reward, done, info
        """
        if self.current_scenario is None:
            raise RuntimeError("Environment not initialized. Call reset() first.")
            
        state_data = self.current_scenario.generate_state()
        outcome = self.current_scenario.calculate_outcome(action, state_data)
        reward = self._calculate_reward(action, outcome)
        done = self.current_scenario.is_terminal()
        next_state_data = self.current_scenario.generate_state()
        next_state = HoneypotState.extract_features(
            next_state_data['attacker_profile'],
            next_state_data['system_state'],
            next_state_data['time_features']
        )
        
        info = {
            'scenario': self.current_scenario.type,
            'outcome': outcome,
            'detected': self.current_scenario.detected,
        }
        
        return next_state, reward, done, info
    
    def _calculate_reward(self, action: int, outcome: dict) -> float:
        """Calculate reward from outcome"""
        reward = 0.0
        
        reward += outcome['data_collected'] * 10.0
        reward += outcome['attacker_time_wasted'] * 8.0
        reward += outcome['attack_prevented'] * 15.0
        reward += outcome['threat_intelligence'] * 12.0
        reward += outcome['deception_successful'] * 20.0
        reward += outcome['stealth_maintained'] * 5.0

        reward -= outcome['system_load'] * 5.0
        reward -= outcome['detection_evasion'] * 50.0
        reward -= outcome['resource_waste'] * 3.0
        
        return reward


def train_honeypot_agent(episodes: int = 5000, checkpoint_dir: str = 'checkpoints'):
    
    os.makedirs(checkpoint_dir, exist_ok=True)
    simulator = HoneypotSimulator()
    agent = HoneypotDDQNAgent()
    
    episode_rewards = []
    episode_lengths = []
    scenario_performance = {s: [] for s in AttackScenario.SCENARIOS.keys()}
    
    print("Starting DDQN Agent Training")
    print("=" * 60)
    
    for episode in range(episodes):
        state, scenario_type = simulator.reset()
        episode_reward = 0
        episode_length = 0
        
        while True:
            action = agent.select_action(state)
            next_state, reward, done, info = simulator.step(action)
            agent.store_experience(state, action, reward, next_state, done)
            if len(agent.memory) >= agent.batch_size:
                loss = agent.train_step()
     
            episode_reward += reward
            episode_length += 1
            agent.steps += 1
            

            if agent.steps % agent.target_update == 0:
                agent.update_target_network()
            
            state = next_state
            
            if done:
                break
        agent.decay_epsilon()
        agent.episode += 1
        episode_rewards.append(episode_reward)
        episode_lengths.append(episode_length)
        scenario_performance[scenario_type].append(episode_reward)
        if (episode + 1) % 100 == 0:
            avg_reward = np.mean(episode_rewards[-100:])
            avg_length = np.mean(episode_lengths[-100:])
            
            print(f"\nEpisode {episode + 1}/{episodes}")
            print(f"Avg Reward (last 100): {avg_reward:.2f}")
            print(f"Avg Length (last 100): {avg_length:.1f}")
            print(f"Epsilon: {agent.epsilon:.4f}")
            print(f"Memory Size: {len(agent.memory)}")
            
            print("\nPerformance by Scenario (last 100):")
            for scenario, rewards in scenario_performance.items():
                if len(rewards) > 0:
                    recent = [r for r in rewards[-100:] if r is not None]
                    if recent:
                        print(f"  {scenario}: {np.mean(recent):.2f}")
        
        if (episode + 1) % 500 == 0:
            checkpoint_path = os.path.join(checkpoint_dir, f'agent_ep{episode+1}.pt')
            agent.save_checkpoint(checkpoint_path)
            print(f"Checkpoint saved: {checkpoint_path}")
    
    final_path = os.path.join(checkpoint_dir, 'agent_final.pt')
    agent.save_checkpoint(final_path)
    
    plot_training_results(episode_rewards, episode_lengths, scenario_performance, checkpoint_dir)
    
    return agent


def plot_training_results(episode_rewards, episode_lengths, scenario_performance, save_dir):
    """Plot and save training metrics"""
    
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    
    ax = axes[0, 0]
    window = 100
    if len(episode_rewards) >= window:
        smoothed = np.convolve(episode_rewards, np.ones(window)/window, mode='valid')
        ax.plot(smoothed)
    else:
        ax.plot(episode_rewards)
    ax.set_title('Episode Rewards (smoothed)')
    ax.set_xlabel('Episode')
    ax.set_ylabel('Reward')
    ax.grid(True)
    
    ax = axes[0, 1]
    if len(episode_lengths) >= window:
        smoothed = np.convolve(episode_lengths, np.ones(window)/window, mode='valid')
        ax.plot(smoothed)
    else:
        ax.plot(episode_lengths)
    ax.set_title('Episode Lengths (smoothed)')
    ax.set_xlabel('Episode')
    ax.set_ylabel('Steps')
    ax.grid(True)
    
    ax = axes[1, 0]
    for scenario, rewards in scenario_performance.items():
        if len(rewards) >= window:
            smoothed = np.convolve(rewards, np.ones(window)/window, mode='valid')
            ax.plot(smoothed, label=scenario, alpha=0.7)
    ax.set_title('Performance by Attack Scenario')
    ax.set_xlabel('Episode')
    ax.set_ylabel('Reward')
    ax.legend(fontsize=8)
    ax.grid(True)
    
    ax = axes[1, 1]
    scenario_avgs = {s: np.mean(r[-500:]) if len(r) >= 500 else np.mean(r) 
                     for s, r in scenario_performance.items() if r}
    if scenario_avgs:
        scenarios = list(scenario_avgs.keys())
        values = list(scenario_avgs.values())
        ax.bar(range(len(scenarios)), values)
        ax.set_xticks(range(len(scenarios)))
        ax.set_xticklabels(scenarios, rotation=45, ha='right')
        ax.set_title('Average Performance by Scenario (last 500)')
        ax.set_ylabel('Avg Reward')
        ax.grid(True, axis='y')
    
    plt.tight_layout()
    plt.savefig(os.path.join(save_dir, 'training_results.png'), dpi=150)
    print(f"Training plots saved to {save_dir}/training_results.png")
    plt.close()


def evaluate_agent(agent: HoneypotDDQNAgent, episodes: int = 100):
    
    simulator = HoneypotSimulator()
    results = {scenario: [] for scenario in AttackScenario.SCENARIOS.keys()}
    
    print("\nEvaluating Agent Performance")
    print("=" * 60)
    
    for episode in range(episodes):
        state, scenario_type = simulator.reset()
        episode_reward = 0
        
        while True:
            action = agent.select_action(state, eval_mode=True)
            next_state, reward, done, info = simulator.step(action)
            
            episode_reward += reward
            state = next_state
            
            if done:
                break
        
        results[scenario_type].append(episode_reward)
    
    print("\nEvaluation Results:")
    for scenario, rewards in results.items():
        if rewards:
            print(f"{scenario:25s}: {np.mean(rewards):8.2f} ± {np.std(rewards):6.2f}")
    
    overall_mean = np.mean([r for rewards in results.values() for r in rewards])
    print(f"\n{'Overall':25s}: {overall_mean:8.2f}")
    
    return results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Train DDQN agent for honeypot')
    parser.add_argument('--episodes', type=int, default=5000, help='Number of training episodes')
    parser.add_argument('--checkpoint-dir', type=str, default='checkpoints', help='Checkpoint directory')
    parser.add_argument('--eval-only', action='store_true', help='Only evaluate existing agent')
    parser.add_argument('--load', type=str, help='Load checkpoint to continue training or evaluate')
    
    args = parser.parse_args()
    
    if args.eval_only:
        if not args.load:
            print("Error: --load required for evaluation")
            exit(1)
        agent = HoneypotDDQNAgent()
        agent.load_checkpoint(args.load)
        evaluate_agent(agent, episodes=100)
    else:
        agent = train_honeypot_agent(
            episodes=args.episodes,
            checkpoint_dir=args.checkpoint_dir
        )
        print("\n" + "=" * 60)
        print("Training Complete! Evaluating final agent...")
        evaluate_agent(agent, episodes=100)
