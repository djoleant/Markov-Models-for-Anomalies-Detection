"""
- IoT system that includes:
    1. Sensors: GPS, accelerometer, CO2, temperature, humidity, PIR, Open-Close.
    2.Gateway
    3. Server
    4. Cloud

- Functions of the Markov Model in this system:
    1. Detection of anomalies in each element of the system for a certain time.
    2. Energy optimizer: the consumption of each sensor is measured with respect to time.
       Once it is known, the states are modified to reduce consumption.
    3. Simulation and control of system network failures.
"""
import random
import matplotlib.pyplot as plt
import numpy as np 
import hashlib
import hmac
import os
from cryptography.fernet import Fernet

class Device:
    def __init__(dev, name, states, matrix_states):
        dev.name = name  # Name of the device
        dev.states = states  # Possible states the device can be in
        dev.matrix_states = matrix_states  # State transition probabilities
        dev.current_state = random.choice(states)  # Initialize with a random state
        dev.state_history = [dev.current_state]  # Keep history of states
        dev.secret_key = os.urandom(16)  # Generate a secure random key for HMAC
        dev.current_state_hash = dev.generate_hash(dev.current_state)  # Generate initial hash for the current state
        # Fernet symmetric encryption key generation
        dev.cipher_suite = Fernet(Fernet.generate_key())
        print(f"{dev.name}: Secret key and encryption key generated.")

    # Generate a hash for a given state using HMAC
    def generate_hash(dev, state):
        hash = hmac.new(dev.secret_key, msg=state.encode(), digestmod=hashlib.sha256).hexdigest()
        print(f"{dev.name}: Hash generated for state '{state}': {hash}")
        return hash

    # Simulate the transition to the next state based on the defined probabilities
    def transition(dev):
        next_state_probs = dev.matrix_states[dev.current_state]
        next_state = random.choices(dev.states, weights=next_state_probs)[0]
        dev.current_state = next_state
        dev.state_history.append(next_state)
        dev.current_state_hash = dev.generate_hash(dev.current_state)
        if len(dev.state_history) > 10:
            dev.state_history.pop(0)  # Limit history size to 10
        return next_state

    # Detect anomalies by comparing the last three states
    def detect_anomalies(dev):
        if len(dev.state_history) >= 3:
            current_state = dev.state_history[-1]
            state_1 = dev.state_history[-2]
            state_2 = dev.state_history[-3]
            if current_state != state_1 and current_state != state_2:
                return True  # Anomaly detected if the current state differs from the last two
        return False

    # Send data securely to the gateway
    def send_data_to_gateway(dev, gateway):
        data = dev.current_state
        hash = dev.generate_hash(data)
        print(f"Device {dev.name}: Sending data to Gateway.")
        if gateway.receive_data_from_device(dev.name, data, hash):
            print(f"Device {dev.name}: Gateway has validated the data correctly.")
        else:
            print(f"Device {dev.name}: Error in data validation at Gateway.")

class Gateway:
    def __init__(gw):
        # Initialize gateway with a secret key for HMAC
        gw.devices_data = {}
        gw.secret_key = os.urandom(16)
        print("Gateway: Secret key has been generated.")

    def receive_data_from_device(gw, device_name, data, hash):
        # verify the integrity of received data using HMAC
        print(f"Gateway: Ciphered data from {device_name}. Verifying the integrity...")
        if hmac.compare_digest(hash, hmac.new(gw.secret_key, msg=data.encode(), digestmod=hashlib.sha256).hexdigest()):
            gw.devices_data[device_name] = data
            print("Gateway: data is validated and stored")
            return True
        else:
            print("Gateway: Failure at verifying the integrity of the data")
            return False

    def send_data_to_server(gw, server):
        # Send validated data to the server, along with a new hash for verification
        for device_name, data in gw.devices_data.items():
            server.receive_data_from_gateway(device_name, data, gw.generate_hash(data))

    def generate_hash(gw, data):
        # Generate a hash for data to ensure integrity
        return hmac.new(gw.secret_key, msg=data.encode(), digestmod=hashlib.sha256).hexdigest()

class Server:
    def __init__(serv, secret_key=None):
        # Initialize server with a secret key and an encryption key
        serv.received_data = {}
        serv.secret_key = secret_key or os.urandom(16)  # Generate new secret key (if there is not)
        serv.encryption_key = Fernet.generate_key()  # Generate encryption key for Fernet
        serv.cipher_suite = Fernet(serv.encryption_key)

    def send_data_to_cloud(serv, cloud, data):
        # Encrypt data before sending to the cloud
        encrypted_data = serv.cipher_suite.encrypt(data.encode())
        signature = serv.generate_signature(data)
        print(f"Server: Sending data to the cloud.")
        cloud.receive_data_from_server('Server1', encrypted_data, signature)

    def generate_signature(serv, data):
        # Generate a signature for data to ensure integrity
        return hmac.new(serv.secret_key, msg=data.encode(), digestmod=hashlib.sha256).hexdigest()

class Cloud:
    def __init__(cl):
        # Initialize cloud storage with a dictionary to store decryption keys
        cl.stored_data = {}
        cl.encryption_keys = {}

    def receive_data_from_server(cl, server_name, data, signature):
        # Simulate SSL/TLS verification and decrypt data if verification is successful
        if cl.verify_data(data, signature):
            decrypted_data = cl.decrypt_data(server_name, data)
            cl.stored_data[server_name] = decrypted_data
            print(f"Cloud: Data received and verifyied {server_name} correctly.")
        else:
            print("Cloud: Failure in verifying the integrity of data received from the server.")

    def register_server(cl, server_name, encryption_key):
        # Register a server's encryption key in the cloud
        print(f"Cloud: Key registered for {server_name}.")
        cl.encryption_keys[server_name] = encryption_key

    def verify_data(cl, data, signature):
        # Assume verification is always correct for simplicity in this model
        return True  

    def decrypt_data(cl, server_name, encrypted_data):
        # Decrypt data using the server's registered encryption key
        cipher_suite = Fernet(cl.encryption_keys[server_name])
        return cipher_suite.decrypt(encrypted_data).decode()
    
class EnergyOptimizer:
    def __init__(dev, devices):
        # Initialize the optimizer with a list of devices
        dev.devices = devices
        # Create a dictionary to store energy consumption history for each device
        dev.energy_history = {device.name: [] for device in devices}

    def optimize_energy(dev, steps):  # Control points for simulation
        for _ in range(steps):
            # Record the state transition for each device
            future_states = {device.name: device.transition() for device in dev.devices}
            # Calculate the total energy cost if devices transition to the next state
            total_energy_cost_on = sum(dev.energy_cost(device, state) for device, state in future_states.items())
            # Calculate the total energy cost if all devices remain in their current state
            total_energy_cost_off = sum(dev.energy_cost(device, device.current_state) for device in dev.devices)

            # Evaluate if it is more cost-effective for each device to transition to a new state or to be turned off
            for device in dev.devices:
                # If the energy cost for a device to change to its future state is less than the total cost when all are on
                if dev.energy_cost(device, future_states[device.name]) < total_energy_cost_on:
                    device.current_state = future_states[device.name]
                else:
                    device.current_state = "Off"
                # Append the calculated energy cost to the device's history
                dev.energy_history[device.name].append(dev.energy_cost(device, device.current_state))

    def energy_cost(dev, device, state):
        # Define the energy cost associated with each state of the device
        energy_costs = {'On': 1, 'Off': 0, 'Normal': 1, 'High Load': 2}
        return energy_costs.get(state, 0)

def plot_energy_sensors(energy_history):
    plt.figure(figsize=(10, 5))
    # Plot energy consumption for each device that is identified as a sensor
    for device, energy_values in energy_history.items():
        if "Sensor" in device:
            plt.plot(range(len(energy_values)), energy_values, label=device)
    plt.xlabel('Time')
    plt.ylabel('Energy consumption')
    plt.title('Sensor energy consumption')
    plt.legend()
    plt.grid(True)
    plt.show()

def plot_average_energy(energy_history):
    plt.figure(figsize=(10, 5))
    # Specify the infrastructure devices
    infrastructure_devices = ['Gateway', 'Server', 'Cloud']
    average_energy = np.zeros(len(energy_history[next(iter(energy_history))]))
    count = 0
    # Calculate the average energy consumption for infrastructure devices
    for device, energy_values in energy_history.items():
        if device in infrastructure_devices:
            average_energy += np.array(energy_values)
            count += 1
    average_energy /= count
    plt.plot(range(len(average_energy)), average_energy, label='Average infrastructure energy')
    plt.xlabel('Time')
    plt.ylabel('Average energy consumption')
    plt.title('Average energy consumption of infrastructure')
    plt.legend()
    plt.grid(True)
    plt.show()
    
def plot_individual_consumption(energy_history):
    """
    Plots the average energy consumption of each category of device within the IoT system.
    Categories are Sensors, Gateway, Server, and Cloud.
    """
    plt.figure(figsize=(12, 6))
    # Dictionary to categorize device energy data
    categories = {'Sensors': [], 'Gateway': [], 'Server': [], 'Cloud': []}

    # Organize energy data into respective categories
    for device, energy in energy_history.items():
        if "Sensor" in device:
            categories['Sensors'].append(energy)
        elif "Gateway" == device:
            categories['Gateway'].append(energy)
        elif "Server" == device:
            categories['Server'].append(energy)
        elif "Cloud" == device:
            categories['Cloud'].append(energy)

    # Calculate and plot average energy consumption for each category
    for category, energies in categories.items():
        if energies:
            average_energy = np.mean(energies, axis=0)
            plt.plot(average_energy, label=f'{category} Avg')

    plt.title('Average energy consumption by element')
    plt.xlabel('Time')
    plt.ylabel('Average energy consumption')
    plt.legend()
    plt.grid(True)
    plt.show()

def simulate_network_state_transitions(num_steps, matrix_states, states):
    """
    Simulates network state transitions using a Markov model.
    """
    current_state = 0  # Start from the first state (e.g., 'Operational')
    state_history = [current_state]  # List to record state history

    # Perform transitions based on probability matrix
    for _ in range(num_steps):
        current_state = np.random.choice(a=len(states), p=matrix_states[current_state])
        state_history.append(current_state)

    return state_history

def detect_network_failures(state_history, failure_state):
    """
    Detects network failures by identifying the indices of the failure state occurrences.
    """
    failure_times = [i for i, state in enumerate(state_history) if state == failure_state]
    return failure_times

def plot_network_failures(state_history, failure_times, states):
    """
    Plots the network state over time and highlights the points of failure.
    """
    time_steps = list(range(len(state_history)))
    state_values = [states[state] for state in state_history]

    plt.figure(figsize=(10, 5))
    plt.plot(time_steps, state_values, label='Network State', marker='o', linestyle='-')

    # Highlight the failure points
    for failure_time in failure_times:
        plt.axvline(x=failure_time, color='r', linestyle='--', label='Failure detected' if failure_time == failure_times[0] else "")

    plt.xlabel('Time (s)')
    plt.ylabel('Network state')
    plt.title('Simulation and Network Failure Detection')
    plt.legend()
    plt.grid(True)
    plt.show()
def main():
    # Initialize the gateway, server, and cloud
    gateway = Gateway()
    server = Server()
    cloud = Cloud()

    # Register the server's encryption key with the cloud for secure communication
    cloud.register_server('Server1', server.encryption_key)
    # Send sensitive data securely to the cloud from the server
    server.send_data_to_cloud(cloud, "Sensitive Data")

    # List of devices including various sensors and network infrastructure components
    devices = [
        Device("Sensor GPS", ['On', 'Off'], {'On': [0.8, 0.2], 'Off': [0.1, 0.9]}),
        Device("Sensor Accelerometer", ['On', 'Off'], {'On': [0.7, 0.3], 'Off': [0.2, 0.8]}),
        Device("Sensor Temperature", ['On', 'Off'], {'On': [0.6, 0.4], 'Off': [0.3, 0.7]}),
        Device("Sensor Humidity", ['On', 'Off'], {'On': [0.5, 0.5], 'Off': [0.4, 0.6]}),
        Device("Sensor Light", ['On', 'Off'], {'On': [0.4, 0.6], 'Off': [0.5, 0.5]}),
        Device("Sensor CO2", ['On', 'Off'], {'On': [0.3, 0.7], 'Off': [0.6, 0.4]}),
        Device("Sensor PIR", ['On', 'Off'], {'On': [0.2, 0.8], 'Off': [0.7, 0.3]}),
        Device("Gateway", ['Normal', 'High Load', 'Off'], {'Normal': [0.9, 0.09, 0.01], 'High Load': [0.5, 0.49, 0.01], 'Off': [0.02, 0.08, 0.9]}),
        Device("Server", ['Normal', 'High Load', 'Off'], {'Normal': [0.95, 0.04, 0.01], 'High Load': [0.3, 0.69, 0.01], 'Off': [0.1, 0.2, 0.7]}),
        Device("Cloud", ['Normal', 'High Load', 'Off'], {'Normal': [0.9, 0.09, 0.01], 'High Load': [0.4, 0.59, 0.01], 'Off': [0.05, 0.15, 0.8]})
    ]

    # Simulate data transmission from devices to gateway and from gateway to server
    for device in devices:
        device.send_data_to_gateway(gateway)
        gateway.send_data_to_server(server)

    # Initialize and run the energy optimizer for the devices
    energy_optimizer = EnergyOptimizer(devices)
    energy_optimizer.optimize_energy(50)

    # Detect anomalies in all devices
    for device in devices:
        if device.detect_anomalies():
            print(f"Anomaly detected in {device.name}")

    # Visualize energy consumption of sensors and overall infrastructure
    plot_energy_sensors(energy_optimizer.energy_history)
    plot_average_energy(energy_optimizer.energy_history)
    plot_individual_consumption(energy_optimizer.energy_history)

    # Define the states and the transition matrix for the network simulation
    states = ['Operational', 'Degraded', 'Failure']
    matrix_states = [
        [0.9, 0.09, 0.01],  # Probabilities of staying Operational, transitioning to Degraded, or to Failure
        [0.1, 0.8, 0.1],    # Probabilities from Degraded to Operational, staying Degraded, or to Failure
        [0.05, 0.15, 0.8]   # Probabilities from Failure to Operational, to Degraded, or staying in Failure
    ]

    # Simulate network state transitions
    num_steps = 100
    state_history = simulate_network_state_transitions(num_steps, matrix_states, states)

    # Detect failures based on the simulated state transitions
    failure_state_index = states.index('Failure')  # Assuming 'Failure' is the third state
    failure_times = detect_network_failures(state_history, failure_state_index)

    # Visualize the network state transitions and highlight failures
    plot_network_failures(state_history, failure_times, states)

if __name__ == "__main__":
    main()


