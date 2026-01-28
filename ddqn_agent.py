#!/usr/bin/env python3
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import random
from collections import deque, namedtuple
from datetime import datetime
import json
import os

Experience = namedtuple('Experience', ['state', 'action', 'reward', 'next_state', 'done'])


class DuelingDQN(nn.Module):
    """Dueling Double DQN Network Architecture"""
    
    def __init__(self, state_dim, action_dim, hidden_dim=256):
        super(DuelingDQN, self).__init__()
        self.feature = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2)
        )
        self.value_stream = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1)
        )
        self.advantage_stream = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, action_dim)
        )
        
    def forward(self, x):
        features = self.feature(x)
        value = self.value_stream(features)
        advantage = self.advantage_stream(features)
        q_values = value + (advantage - advantage.mean(dim=1, keepdim=True))
        return q_values


class PrioritizedReplayBuffer:
    
    def __init__(self, capacity, alpha=0.6):
        self.capacity = capacity
        self.alpha = alpha
        self.buffer = []
        self.priorities = np.zeros(capacity, dtype=np.float32)
        self.position = 0
        
    def push(self, experience):
        max_priority = self.priorities.max() if self.buffer else 1.0
        
        if len(self.buffer) < self.capacity:
            self.buffer.append(experience)
        else:
            self.buffer[self.position] = experience
            
        self.priorities[self.position] = max_priority
        self.position = (self.position + 1) % self.capacity
        
    def sample(self, batch_size, beta=0.4):
        if len(self.buffer) == 0:
            return None
            
        priorities = self.priorities[:len(self.buffer)]
        probabilities = priorities ** self.alpha
        probabilities /= probabilities.sum()
        
        indices = np.random.choice(len(self.buffer), batch_size, p=probabilities, replace=False)
        samples = [self.buffer[idx] for idx in indices]
        total = len(self.buffer)
        weights = (total * probabilities[indices]) ** (-beta)
        weights /= weights.max()
        
        return samples, indices, weights
    
    def update_priorities(self, indices, priorities):
        for idx, priority in zip(indices, priorities):
            self.priorities[idx] = priority
            
    def __len__(self):
        return len(self.buffer)


class HoneypotState:
    
    @staticmethod
    def extract_features(attacker_profile, system_state, time_features):
        features = []
        
        features.extend([
            attacker_profile.get('request_rate', 0) / 100.0, 
            attacker_profile.get('unique_paths', 0) / 50.0,
            attacker_profile.get('failed_logins', 0) / 20.0,
            attacker_profile.get('port_scans', 0) / 100.0,
            attacker_profile.get('payload_size_avg', 0) / 10000.0,
            float(attacker_profile.get('is_known_attacker', 0)),
            float(attacker_profile.get('suspicious_ua', 0)),
            attacker_profile.get('session_duration', 0) / 3600.0, 
        ])
        
        features.extend([
            float(attacker_profile.get('sql_injection_attempts', 0) > 0),
            float(attacker_profile.get('xss_attempts', 0) > 0),
            float(attacker_profile.get('path_traversal_attempts', 0) > 0),
            float(attacker_profile.get('brute_force_detected', 0)),
            float(attacker_profile.get('credential_stuffing', 0)),
        ])
        
        features.extend([
            system_state.get('cpu_usage', 0) / 100.0,
            system_state.get('memory_usage', 0) / 100.0,
            system_state.get('active_connections', 0) / 1000.0,
            system_state.get('thread_count', 0) / 500.0,
            float(system_state.get('under_attack', 0)),
        ])
        
        features.extend([
            time_features.get('hour', 0) / 24.0,
            time_features.get('day_of_week', 0) / 7.0,
            float(time_features.get('is_weekend', 0)),
            time_features.get('time_since_last_attack', 0) / 3600.0,
        ])
        
        return np.array(features, dtype=np.float32)


class HoneypotDDQNAgent:
    ACTIONS = {
        0: 'observe_silent',       # Silently log, minimal response
        1: 'engage_low',            # Basic interaction, collect more data
        2: 'engage_medium',         # Moderate interaction, feed misinformation
        3: 'engage_high',           # Deep engagement, advanced deception
        4: 'rate_limit',            # Apply rate limiting
        5: 'temporary_block',       # Temporary IP block
        6: 'tarpit',                # Slow down attacker (tarpit technique)
        7: 'redirect_decoy',        # Redirect to high-interaction honeypot
        8: 'alert_escalate',        # Escalate to security team
    }
    
    def __init__(self, state_dim=22, action_dim=9, config=None):
        self.state_dim = state_dim
        self.action_dim = action_dim
        
        self.config = config or {}
        self.gamma = self.config.get('gamma', 0.99)
        self.epsilon_start = self.config.get('epsilon_start', 1.0)
        self.epsilon_end = self.config.get('epsilon_end', 0.01)
        self.epsilon_decay = self.config.get('epsilon_decay', 0.995)
        self.learning_rate = self.config.get('learning_rate', 0.0001)
        self.batch_size = self.config.get('batch_size', 64)
        self.target_update = self.config.get('target_update', 10)
        self.memory_size = self.config.get('memory_size', 100000)
        
        self.epsilon = self.epsilon_start
        self.steps = 0
        self.episode = 0
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.policy_net = DuelingDQN(state_dim, action_dim).to(self.device)
        self.target_net = DuelingDQN(state_dim, action_dim).to(self.device)
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()
        
        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=self.learning_rate)
        self.memory = PrioritizedReplayBuffer(self.memory_size)
        self.metrics = {
            'episode_rewards': [],
            'episode_lengths': [],
            'losses': [],
            'epsilon_values': [],
            'action_distribution': {i: 0 for i in range(action_dim)}
        }
        
    def select_action(self, state, eval_mode=False):
        if not eval_mode and random.random() < self.epsilon:
            action = random.randrange(self.action_dim)
        else:
            with torch.no_grad():
                state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
                q_values = self.policy_net(state_tensor)
                action = q_values.max(1)[1].item()
        
        self.metrics['action_distribution'][action] += 1
        return action
    
    def store_experience(self, state, action, reward, next_state, done):
        experience = Experience(state, action, reward, next_state, done)
        self.memory.push(experience)
        
    def calculate_reward(self, action, outcome):
        reward = 0.0
        
        reward += outcome.get('data_collected', 0) * 10.0
        reward += outcome.get('attacker_time_wasted', 0) * 5.0
        reward += outcome.get('attack_prevented', 0) * 20.0
        reward += outcome.get('threat_intelligence', 0) * 15.0
  
        reward -= outcome.get('system_load', 0) * 3.0
        reward -= outcome.get('detection_evasion', 0) * 50.0
        reward -= outcome.get('resource_waste', 0) * 2.0
        
        if action == 0 and outcome.get('stealth_maintained', 0):
            reward += 5.0
        elif action in [2, 3] and outcome.get('deception_successful', 0):
            reward += 25.0
        elif action == 7 and outcome.get('redirected_successfully', 0):
            reward += 30.0
            
        return reward
    
    def train_step(self):
        """Perform one training step"""
        if len(self.memory) < self.batch_size:
            return None
        beta = min(1.0, 0.4 + self.steps * (1.0 - 0.4) / 100000)
        samples, indices, weights = self.memory.sample(self.batch_size, beta)
        
        if samples is None:
            return None
        batch = Experience(*zip(*samples))
        state_batch = torch.FloatTensor(np.array(batch.state)).to(self.device)
        action_batch = torch.LongTensor(batch.action).to(self.device)
        reward_batch = torch.FloatTensor(batch.reward).to(self.device)
        next_state_batch = torch.FloatTensor(np.array(batch.next_state)).to(self.device)
        done_batch = torch.FloatTensor(batch.done).to(self.device)
        weights_batch = torch.FloatTensor(weights).to(self.device)
        current_q_values = self.policy_net(state_batch).gather(1, action_batch.unsqueeze(1))
        with torch.no_grad():
            next_actions = self.policy_net(next_state_batch).max(1)[1].unsqueeze(1)
            next_q_values = self.target_net(next_state_batch).gather(1, next_actions).squeeze(1)
            target_q_values = reward_batch + (1 - done_batch) * self.gamma * next_q_values
        
        # Compute loss with importance sampling weights
        td_errors = target_q_values.unsqueeze(1) - current_q_values
        loss = (weights_batch * td_errors.pow(2)).mean()
        
        # Optimize
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.policy_net.parameters(), 10.0)
        self.optimizer.step()
        
        # Update priorities
        priorities = td_errors.abs().detach().cpu().numpy() + 1e-6
        self.memory.update_priorities(indices, priorities)
        
        self.metrics['losses'].append(loss.item())
        return loss.item()
    
    def update_target_network(self):
        """Update target network with policy network weights"""
        self.target_net.load_state_dict(self.policy_net.state_dict())
    
    def decay_epsilon(self):
        """Decay exploration rate"""
        self.epsilon = max(self.epsilon_end, self.epsilon * self.epsilon_decay)
        self.metrics['epsilon_values'].append(self.epsilon)
    
    def save_checkpoint(self, filepath):
        """Save agent checkpoint"""
        checkpoint = {
            'policy_net_state_dict': self.policy_net.state_dict(),
            'target_net_state_dict': self.target_net.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'epsilon': self.epsilon,
            'steps': self.steps,
            'episode': self.episode,
            'metrics': self.metrics,
            'config': self.config
        }
        torch.save(checkpoint, filepath)
        print(f"Checkpoint saved to {filepath}")
    
    def load_checkpoint(self, filepath):
        """Load agent checkpoint"""
        if not os.path.exists(filepath):
            print(f"Checkpoint {filepath} not found")
            return False
            
        checkpoint = torch.load(filepath, map_location=self.device)
        self.policy_net.load_state_dict(checkpoint['policy_net_state_dict'])
        self.target_net.load_state_dict(checkpoint['target_net_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.epsilon = checkpoint['epsilon']
        self.steps = checkpoint['steps']
        self.episode = checkpoint['episode']
        self.metrics = checkpoint['metrics']
        print(f"Checkpoint loaded from {filepath}")
        return True
    
    def get_action_name(self, action):
        """Get human-readable action name"""
        return self.ACTIONS.get(action, 'unknown')
    
    def print_metrics(self):
        """Print training metrics"""
        if len(self.metrics['episode_rewards']) > 0:
            recent_rewards = self.metrics['episode_rewards'][-100:]
            avg_reward = np.mean(recent_rewards)
            print(f"\nEpisode: {self.episode}")
            print(f"Avg Reward (last 100): {avg_reward:.2f}")
            print(f"Epsilon: {self.epsilon:.4f}")
            if len(self.metrics['losses']) > 0:
                print(f"Avg Loss (last 100): {np.mean(self.metrics['losses'][-100:]):.4f}")
            print(f"Memory Size: {len(self.memory)}")
            print("\nAction Distribution:")
            total_actions = sum(self.metrics['action_distribution'].values())
            for action_id, count in sorted(self.metrics['action_distribution'].items()):
                pct = (count / total_actions * 100) if total_actions > 0 else 0
                print(f"  {action_id} ({self.ACTIONS[action_id]}): {count} ({pct:.1f}%)")


def train_agent(num_episodes=1000, checkpoint_dir='checkpoints'):
    """Training loop for honeypot DDQN agent"""
    os.makedirs(checkpoint_dir, exist_ok=True)
    
    agent = HoneypotDDQNAgent()
    
    for episode in range(num_episodes):
        agent.episode = episode
        episode_reward = 0
        episode_length = 0
        state = HoneypotState.extract_features(
            attacker_profile={'request_rate': 10, 'failed_logins': 2},
            system_state={'cpu_usage': 20, 'memory_usage': 30},
            time_features={'hour': 14, 'day_of_week': 3}
        )
        
        done = False
        while not done:
            action = agent.select_action(state)
            outcome = {
                'data_collected': np.random.uniform(0, 1),
                'attacker_time_wasted': np.random.uniform(0, 10),
                'system_load': np.random.uniform(0, 0.5),
                'detection_evasion': np.random.choice([0, 1], p=[0.9, 0.1]),
            }
            
            reward = agent.calculate_reward(action, outcome)
            next_state = state + np.random.randn(agent.state_dim) * 0.1
            done = episode_length > 100 or np.random.random() < 0.01
            agent.store_experience(state, action, reward, next_state, done)
            loss = agent.train_step()
            
            state = next_state
            episode_reward += reward
            episode_length += 1
            agent.steps += 1
            if agent.steps % agent.target_update == 0:
                agent.update_target_network()
        
        agent.decay_epsilon()
        agent.metrics['episode_rewards'].append(episode_reward)
        agent.metrics['episode_lengths'].append(episode_length)

        if (episode + 1) % 10 == 0:
            agent.print_metrics()
        
        if (episode + 1) % 100 == 0:
            checkpoint_path = os.path.join(checkpoint_dir, f'agent_episode_{episode+1}.pt')
            agent.save_checkpoint(checkpoint_path)
    
    return agent


if __name__ == "__main__":
    print("Training DDQN Agent for Honeypot Defense...")
    agent = train_agent(num_episodes=1000)
    print("\nTraining complete!")
